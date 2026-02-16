// Copyright (C) 2024, 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Tracing logic
//!
//! This module provides the [`Tracer`], which processes tracing packet
//! [`InstructionTrace`] payloads and generates streams of tracing [`Item`]s.

pub mod error;
pub mod item;
mod state;

pub use item::Item;

use crate::binary::{self, Binary};
use crate::config::{self, AddressMode, Features, Version};
use crate::instruction;
use crate::packet::payload::{InstructionTrace, Payload};
use crate::packet::sync;
use crate::packet::unit::IOptions;
use crate::types::{self, stack, trap};

use error::Error;
use instruction::info::Info;
use stack::ReturnStack;

/// Tracer
///
/// A tracer processes packet [`InstructionTrace`] payloads for a single RISC-V
/// hart and generates [`Item`]s for that hart.
///
/// Individual [`InstructionTrace`] payloads are fed to the tracer through
/// [`process_payload`][Self::process_payload]. Alternatively, specific types of
/// paylaods may be fed through more specialized fns. After a payload was fed to
/// the tracer, [`Item`]s become availible via the tracer's [`Iterator`]
/// implementation.
///
/// After all [`Item`]s were extracted, the next payload may be fed to the
/// tracer. Feeding a payload while the items generated from the last payload
/// are not exhaused results in an error.
///
/// Tracers are constructed using a [`Builder`].
///
/// # Example
///
/// The following example demonstrates feeding a payload to a tracer and then
/// iterating over the generated [`Item`]s.
///
/// ```
/// use riscv_etrace::tracer;
///
/// # use riscv_etrace::instruction::COMPRESSED;
/// # let code = riscv_etrace::binary::from_sorted_map([(0x28, COMPRESSED)]);
/// let parameters = Default::default();
/// let mut tracer: tracer::Tracer<_> = tracer::builder()
///     .with_binary(code)
///     .with_params(&parameters)
///     .build()
///     .unwrap();
///
/// # use riscv_etrace::packet;
/// # use packet::payload::{InstructionTrace, Payload};
/// # let payload: Payload = InstructionTrace::from(
/// #   packet::sync::Start {
/// #       branch: false,
/// #       ctx: Default::default(),
/// #       address: 0x28,
/// #   }
/// # )
/// # .into();
/// tracer.process_payload(&payload).unwrap();
/// tracer.by_ref().for_each(|i| {
///     println!("PC: {:0x}", i.unwrap().pc());
/// });
/// ```
pub struct Tracer<B, S = stack::NoStack, I = Option<instruction::Kind>>
where
    B: Binary<I>,
    S: ReturnStack,
    I: Info,
{
    state: state::State<S, I>,
    iter_state: IterationState,
    previous: Option<Event>,
    binary: B,
    address_mode: AddressMode,
    phantom: core::marker::PhantomData<I>,
}

impl<B: Binary<I>, S: ReturnStack, I: Info + Clone> Tracer<B, S, I> {
    /// Retrieve the current selection of optional [Features]
    pub fn features(&self) -> Features {
        self.state.features()
    }

    /// Get a reference of the [`Binary`] used by this tracer
    pub fn binary(&self) -> &B {
        &self.binary
    }

    /// Get a mutable reference of the [`Binary`] used by this tracer
    pub fn binary_mut(&mut self) -> &mut B {
        &mut self.binary
    }

    /// Process an [`Payload`]
    ///
    /// The tracer will yield new trace [`Item`]s after receiving most types of
    /// payloads via this fn.
    pub fn process_payload<D>(
        &mut self,
        payload: &Payload<impl IOptions, D>,
    ) -> Result<(), Error<B::Error>> {
        match payload {
            Payload::InstructionTrace(p) => self.process_te_inst(p),
            _ => Ok(()),
        }
    }

    /// Process an [`InstructionTrace`] payload
    ///
    /// The tracer will yield new trace [`Item`]s after receiving most types of
    /// payloads via this fn.
    pub fn process_te_inst<D>(
        &mut self,
        payload: &InstructionTrace<impl IOptions, D>,
    ) -> Result<(), Error<B::Error>> {
        use state::StopCondition;

        if let InstructionTrace::Synchronization(sync) = payload {
            self.process_sync(sync)
        } else {
            let previous = self.previous.take();
            let updiscon_prev = self.state.previous_insn().is_uninferable_discon();

            let mut initer = self.state.initializer(&mut self.binary)?;
            initer.set_stack_depth(payload.implicit_return_depth());

            if let InstructionTrace::Branch(branch) = payload {
                initer
                    .get_branch_map_mut()
                    .append(branch.branch_map)
                    .map_err(Error::CannotAddBranches)?;
            }
            let condition = if let Some(info) = payload.get_address_info() {
                let notify = info.notify;
                self.previous = Some(Event::Address { notify });
                match self.address_mode {
                    AddressMode::Full => initer.set_address(0u64.wrapping_add_signed(info.address)),
                    AddressMode::Delta => initer.set_rel_address(info.address),
                }

                StopCondition::Address {
                    notify,
                    not_updiscon: !info.updiscon,
                }
            } else {
                StopCondition::LastBranch
            };

            if !updiscon_prev && previous == Some(Event::Address { notify: false }) {
                initer.set_inferred();
            }
            initer.set_condition(condition);

            Ok(())
        }
    }

    /// Process a [`sync::Synchronization`]
    ///
    /// After a call to this fn, the tracer may yield new trace
    /// [`Item`]s.
    pub fn process_sync<D>(
        &mut self,
        sync: &sync::Synchronization<impl IOptions, D>,
    ) -> Result<(), Error<B::Error>> {
        use sync::Synchronization;

        let previous = self.previous.take();
        match sync {
            Synchronization::Start(start) => {
                let is_tracing = self.iter_state.is_tracing();

                let mut initer = self.sync_init(start.address, !is_tracing, !start.branch)?;
                if is_tracing && previous != Some(Event::Trap { thaddr: false }) {
                    initer.set_condition(state::StopCondition::Sync {
                        context: start.ctx.into(),
                    });
                } else {
                    initer.set_context(start.ctx.into());
                    initer.reset_to_address()?;
                    self.iter_state = IterationState::ContextItem {
                        pc: None,
                        context: start.ctx.into(),
                        follow_up: true,
                    };
                }
            }
            Synchronization::Trap(trap) => {
                let thaddr = trap.thaddr;
                self.previous = Some(Event::Trap { thaddr });
                let epc = if trap.info.is_exception()
                    && previous != Some(Event::Trap { thaddr: false })
                {
                    let epc = (!trap.thaddr).then_some(trap.address);
                    self.state.exception_address(&mut self.binary, epc)?
                } else {
                    self.state.current_pc()
                };
                if !thaddr {
                    let mut initer = self.state.initializer(&mut self.binary)?;
                    initer.set_stack_depth(None);
                    initer.set_address(trap.address);
                    initer.reset_to_address()?;
                } else {
                    let mut initer = self.sync_init(trap.address, false, !trap.branch)?;
                    initer.set_context(trap.ctx.into());
                    initer.reset_to_address()?;
                }
                self.iter_state = IterationState::TrapItem {
                    epc,
                    info: trap.info,
                    context: trap.ctx.into(),
                    follow_up: thaddr,
                };
            }
            Synchronization::Context(ctx) => {
                let mut initer = self.state.initializer(&mut self.binary)?;
                initer.set_stack_depth(None);
                initer.set_context(ctx.into());
                self.iter_state = IterationState::ContextItem {
                    pc: None,
                    context: ctx.into(),
                    follow_up: false,
                };
            }
            Synchronization::Support(sup) => {
                self.process_support(sup)?;
            }
        }

        Ok(())
    }

    /// Process a [`sync::Support`]
    ///
    /// After a call to this fn, the tracer may yield new trace
    /// [`Item`]s.
    pub fn process_support<D>(
        &mut self,
        support: &sync::Support<impl IOptions, D>,
    ) -> Result<(), Error<B::Error>> {
        use sync::QualStatus;

        self.previous = None;

        let mut initer = self.state.initializer(&mut self.binary)?;
        support
            .ioptions
            .update_features(initer.get_features_mut())
            .map_err(Error::UnsupportedFeature)?;

        if let Some(mode) = support.ioptions.address_mode() {
            self.address_mode = mode;
        }

        initer.set_stack_depth(None);

        let qual_status = support.qual_status;
        if qual_status != QualStatus::NoChange {
            self.iter_state = IterationState::Depleting { qual_status };

            if qual_status == QualStatus::EndedNtr && initer.update_inferred() {
                initer.set_condition(state::StopCondition::NotInferred);
            }
        }
        Ok(())
    }

    /// Determine whether this tracer is in the tracing state
    ///
    /// A tracer enters the tracing state when processing a [`sync::Start`]
    /// payload and leaves the state when receiving a [`sync::Support`] payload
    /// indicating end or loss of trace.
    pub fn is_tracing(&self) -> bool {
        self.iter_state.is_tracing()
    }

    /// Retrieve the current [`sync::QualStatus`] if availible
    ///
    /// After processing of a [`sync::Support`] signalling end or loss of trace,
    /// this fn returns the associated [`sync::QualStatus`]. In addition, the
    /// [`Default`] status will be returned before tracing start.
    pub fn qual_status(&self) -> Option<sync::QualStatus> {
        match &self.iter_state {
            IterationState::Depleting { qual_status } => Some(*qual_status),
            _ => None,
        }
    }

    /// Create a [`state::Initializer`] for [`sync::Synchronization`] variants
    fn sync_init(
        &mut self,
        address: u64,
        reset_branch_map: bool,
        branch_taken: bool,
    ) -> Result<state::Initializer<'_, S, B, I>, Error<B::Error>> {
        use instruction::info::Info;

        let insn = self
            .binary
            .get_insn(address)
            .map_err(|e| Error::CannotGetInstruction(e, address))?;
        let mut initer = self.state.initializer(&mut self.binary)?;

        initer.set_address(address);

        let branch_map = initer.get_branch_map_mut();
        if reset_branch_map {
            *branch_map = Default::default();
        }
        if insn.is_branch() {
            branch_map
                .push_branch_taken(branch_taken)
                .map_err(Error::CannotAddBranches)?;
        }

        initer.set_stack_depth(None);

        Ok(initer)
    }
}

impl<B: Binary<I>, S: ReturnStack, I: Info + Clone> Iterator for Tracer<B, S, I> {
    type Item = Result<Item<I>, Error<B::Error>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter_state {
            IterationState::SingleItem => {
                self.iter_state = IterationState::FollowExec;

                Some(Ok(Item::new(
                    self.state.current_pc(),
                    self.state.current_insn().into(),
                )))
            }
            IterationState::TrapItem {
                epc,
                info,
                context,
                follow_up,
            } => {
                let pc = (!follow_up).then_some(epc);
                self.iter_state = IterationState::ContextItem {
                    pc,
                    context,
                    follow_up,
                };

                Some(Ok(Item::new(epc, info.into())))
            }
            IterationState::ContextItem {
                pc,
                context,
                follow_up,
            } => {
                self.iter_state = if follow_up {
                    IterationState::SingleItem
                } else {
                    IterationState::FollowExec
                };

                let pc = pc.unwrap_or(self.state.current_pc());
                Some(Ok(Item::new(pc, context.into())))
            }
            IterationState::FollowExec | IterationState::Depleting { .. } => {
                let res = self
                    .state
                    .next_item(&mut self.binary)
                    .transpose()?
                    .map(|(p, i, c)| {
                        if let Some(ctx) = c {
                            self.iter_state = IterationState::SingleItem;
                            Item::new(p, ctx.into())
                        } else {
                            Item::new(p, i.into())
                        }
                    });
                Some(res)
            }
            IterationState::Recovering => None,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self.iter_state {
            // Depending on follow at least 1 or 2, up to infinite
            IterationState::TrapItem { follow_up, .. } => {
                let n = if follow_up { 2 } else { 1 };
                (n, None)
            }
            IterationState::ContextItem { follow_up, .. } => {
                let n = if follow_up { 2 } else { 1 };
                (n, None)
            }

            // Single Item
            IterationState::SingleItem => (1, Some(1)),

            // Minimum 1 item, but could also be infinite
            IterationState::FollowExec => (0, None),
            IterationState::Depleting { .. } => (0, None),
            IterationState::Recovering => (0, Some(0)),
        }
    }
}

/// Create a new [`Builder`] for [`Tracer`]s
pub fn builder() -> Builder<binary::Empty> {
    Default::default()
}

/// Builder for [`Tracer`]
///
/// A builder will build a single [`Tracer`] for a single RISC-V hart.
///
/// If multiple harts are to be traced, multiple [`Tracer`]s need to be built.
/// For this purpose, [`Builder`] implements [`Copy`] and [`Clone`] as long as
/// the [`Binary`] does.
#[derive(Copy, Clone)]
pub struct Builder<B = binary::Empty> {
    binary: B,
    max_stack_depth: usize,
    features: Features,
    address_mode: AddressMode,
    address_width: core::num::NonZeroU8,
    version: Version,
}

impl Builder<binary::Empty> {
    /// Create a new builder for a [`Tracer`]
    pub fn new() -> Self {
        Default::default()
    }
}

impl<B> Builder<B> {
    /// Build the [`Tracer`] for encoders with the given [`config::Parameters`]
    ///
    /// New builders assume [`Default`] parameters.
    pub fn with_params(self, config: &config::Parameters) -> Self {
        let max_stack_depth = if config.return_stack_size_p > 0 {
            1 << config.return_stack_size_p
        } else if config.call_counter_size_p > 0 {
            1 << config.call_counter_size_p
        } else {
            0
        };
        Self {
            max_stack_depth,
            address_width: config.iaddress_width_p,
            features: Features {
                sequentially_inferred_jumps: config.sijump_p,
                ..self.features
            },
            ..self
        }
    }

    /// Build the [`Tracer`] with the given [`Binary`]
    ///
    /// New builders carry an empty or [`Default`] [`Binary`]. This is usually
    /// not what you want.
    pub fn with_binary<C>(self, binary: C) -> Builder<C> {
        Builder {
            binary,
            max_stack_depth: self.max_stack_depth,
            address_mode: self.address_mode,
            address_width: self.address_width,
            features: self.features,
            version: self.version,
        }
    }

    /// Build a [`Tracer`] for the given [`AddressMode`]
    ///
    /// New builders are configured for [`AddressMode::Delta`].
    pub fn with_address_mode(self, mode: AddressMode) -> Self {
        Self {
            address_mode: mode,
            ..self
        }
    }

    /// Build a [`Tracer`] with implicit return enabled or disabled
    ///
    /// New builders are configured for no implicit return. The option in a
    /// [`Tracer`] is usually controlled via a [support payload][sync::Support].
    pub fn with_implicit_return(self, implicit_returns: bool) -> Self {
        Self {
            features: Features {
                implicit_returns,
                ..self.features
            },
            ..self
        }
    }

    /// Build a [`Tracer`] for the given version of the tracing specification
    ///
    /// New builders are configured for [`Version::V2`]. This setting doesn't
    /// currently have any effect as version 2 tracing also allows processing
    /// version 1 traces.
    pub fn with_version(self, version: Version) -> Self {
        Self { version, ..self }
    }

    /// Build the [`Tracer`]
    pub fn build<S, I>(self) -> Result<Tracer<B, S, I>, Error<B::Error>>
    where
        B: Binary<I>,
        S: ReturnStack,
        I: Info + Clone,
    {
        let state = state::State::new(
            S::new(self.max_stack_depth)
                .ok_or(Error::CannotConstructIrStack(self.max_stack_depth))?,
            self.address_width,
            self.features,
        );
        Ok(Tracer {
            state,
            iter_state: Default::default(),
            previous: Default::default(),
            binary: self.binary,
            address_mode: self.address_mode,
            phantom: Default::default(),
        })
    }
}

impl<B: Default> Default for Builder<B> {
    fn default() -> Self {
        Self {
            binary: Default::default(),
            max_stack_depth: Default::default(),
            features: Default::default(),
            address_mode: Default::default(),
            address_width: core::num::NonZeroU8::MIN,
            version: Default::default(),
        }
        .with_params(&Default::default())
    }
}

/// [`Tracer`] iteration states
#[derive(Copy, Clone, Debug)]
enum IterationState {
    /// The [`Tracer`] reports a single item (the current one)
    SingleItem,
    /// We report a trap item and optionally a follow-up single item
    TrapItem {
        epc: u64,
        info: trap::Info,
        context: types::Context,
        follow_up: bool,
    },
    /// We report a context update and optionally a single follow-up item
    ContextItem {
        pc: Option<u64>,
        context: types::Context,
        follow_up: bool,
    },
    /// We follow the execution path based on the current packet's data
    FollowExec,
    /// We follow the execution path as long as it's inferable
    Depleting { qual_status: sync::QualStatus },
    /// We are recovering from some error
    Recovering,
}

impl IterationState {
    /// Check whether we are currently tracing, assuming we depleted all items
    pub fn is_tracing(&self) -> bool {
        !matches!(self, Self::Depleting { .. })
    }

    /// Check whether we are currently recovering from a failure
    pub fn is_recovering(&self) -> bool {
        matches!(self, Self::Recovering)
    }

    /// Handle a [`Result`], entering recovery mode if it is an error
    fn handle_result<T, E>(&mut self, res: Result<T, E>) -> Result<T, E> {
        if res.is_err() {
            *self = IterationState::Recovering;
        }

        res
    }
}

impl Default for IterationState {
    fn default() -> Self {
        Self::Depleting {
            qual_status: Default::default(),
        }
    }
}

/// Categorization of a subset of all events communicated via [`payload::InstrucitonTrace`]
#[derive(Copy, Clone, Debug, PartialEq)]
enum Event {
    /// The last event carried a [`payload::AddressInfo`]
    Address {
        /// Value of the [`payload::AddressInfo`]'s `notify`
        notify: bool,
    },
    /// The last event was a [`sync::Trap`]
    Trap {
        /// Value of the [`sync::Trap`]'s `thaddr`
        thaddr: bool,
    },
}
