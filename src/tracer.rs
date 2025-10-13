// Copyright (C) 2024, 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Tracing logic
//!
//! This module provides the [`Tracer`], which processes tracing packet
//! [`InstructionTrace`] payloads and generates streams of tracing [`Item`]s.

pub mod error;
pub mod item;
pub mod stack;
mod state;

#[cfg(test)]
mod tests;

pub use item::Item;

use crate::binary::{self, Binary};
use crate::config::{self, AddressMode, Version};
use crate::decoder::payload::{InstructionTrace, Payload};
use crate::decoder::sync;
use crate::decoder::unit::IOptions;
use crate::instruction;
use crate::types::trap;

use error::Error;
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
/// # use riscv_etrace::decoder;
/// # use decoder::payload::{InstructionTrace, Payload};
/// # let payload: Payload = InstructionTrace::from(
/// #   decoder::sync::Start {
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
pub struct Tracer<B: Binary, S: ReturnStack = stack::NoStack> {
    state: state::State<S>,
    iter_state: IterationState,
    exception_previous: bool,
    binary: B,
    address_mode: AddressMode,
    address_delta_width: core::num::NonZeroU8,
    version: Version,
}

impl<B: Binary, S: ReturnStack> Tracer<B, S> {
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
            self.exception_previous = false;
            let mut initer = self.state.initializer(&mut self.binary)?;
            initer.set_stack_depth(payload.implicit_return_depth());

            if let InstructionTrace::Branch(branch) = payload {
                initer.get_branch_map_mut().append(branch.branch_map);
            }
            if let Some(info) = payload.get_address_info() {
                match self.address_mode {
                    AddressMode::Full => initer.set_address(info.address),
                    AddressMode::Delta => {
                        let width = self.address_delta_width.get();
                        let mut address = info.address;
                        if address >> (width - 1) != 0 {
                            address |= u64::MAX.checked_shl(width.into()).unwrap_or(0);
                        }
                        initer.set_rel_address(address);
                    }
                }

                initer.set_condition(StopCondition::Address {
                    notify: info.notify,
                    not_updiscon: !info.updiscon,
                });
            } else {
                initer.set_condition(StopCondition::LastBranch);
            }
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

        let exception_previous = self.exception_previous;
        self.exception_previous = false;
        match sync {
            Synchronization::Start(start) => {
                let is_tracing = self.iter_state.is_tracing();
                let version = self.version;

                let mut initer = self.sync_init(start.address, !is_tracing, !start.branch)?;
                if is_tracing && !exception_previous {
                    let action = match version {
                        Version::V1 => state::SyncAction::Compare,
                        _ => state::SyncAction::Update,
                    };
                    initer.set_condition(state::StopCondition::Sync {
                        context: start.ctx.into(),
                        action,
                    });
                } else {
                    if version != Version::V1 {
                        initer.set_context(start.ctx.into());
                    }
                    initer.reset_to_address()?;
                    self.iter_state = IterationState::ContextItem {
                        pc: None,
                        context: start.ctx.into(),
                        follow_up: true,
                    };
                }
            }
            Synchronization::Trap(trap) => {
                let epc = if trap.info.is_exception() && !exception_previous {
                    let epc = (!trap.thaddr).then_some(trap.address);
                    self.state.exception_address(&mut self.binary, epc)?
                } else {
                    self.state.current_pc()
                };
                if !trap.thaddr {
                    self.exception_previous = true;
                    let mut initer = self.state.initializer(&mut self.binary)?;
                    initer.set_stack_depth(None);
                    initer.set_address(trap.address);
                    initer.reset_to_address()?;
                } else {
                    let version = self.version;
                    let mut initer = self.sync_init(trap.address, false, !trap.branch)?;
                    if version != Version::V1 {
                        initer.set_context(trap.ctx.into());
                    }
                    initer.reset_to_address()?;
                }
                self.iter_state = IterationState::TrapItem {
                    epc,
                    info: trap.info,
                    context: trap.ctx.into(),
                    follow_up: trap.thaddr,
                };
            }
            Synchronization::Context(ctx) => {
                let mut initer = self.state.initializer(&mut self.binary)?;
                initer.set_stack_depth(None);
                if self.version != Version::V1 {
                    initer.set_context(ctx.into());
                }
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

        // Before touching any state, we need to assert no unsupported option is
        // active.
        if support.ioptions.implicit_exception() == Some(true) {
            return Err(Error::UnsupportedFeature("implicit exceptions"));
        }
        if support.ioptions.branch_prediction() == Some(true) {
            return Err(Error::UnsupportedFeature("branch prediction"));
        }
        if support.ioptions.jump_target_cache() == Some(true) {
            return Err(Error::UnsupportedFeature("jump target cache"));
        }

        self.exception_previous = false;
        let mut initer = self.state.initializer(&mut self.binary)?;

        if let Some(mode) = support.ioptions.address_mode() {
            self.address_mode = mode;
        }
        if let Some(jumps) = support.ioptions.sequentially_inferred_jumps() {
            initer.set_sequential_jumps(jumps);
        }
        if let Some(returns) = support.ioptions.implicit_return() {
            initer.set_implicit_return(returns);
        }

        initer.set_stack_depth(None);

        if support.qual_status != QualStatus::NoChange {
            self.iter_state = IterationState::Depleting;

            if support.qual_status == QualStatus::EndedNtr && initer.update_inferred() {
                initer.set_condition(state::StopCondition::NotInferred);
            }
        }
        Ok(())
    }

    /// Create a [`state::Initializer`] for [`sync::Synchronization`] variants
    fn sync_init(
        &mut self,
        address: u64,
        reset_branch_map: bool,
        branch_taken: bool,
    ) -> Result<state::Initializer<'_, S, B>, Error<B::Error>> {
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
        if insn
            .kind
            .and_then(instruction::Kind::branch_target)
            .is_some()
        {
            branch_map.push_branch_taken(branch_taken);
        }

        initer.set_stack_depth(None);

        Ok(initer)
    }
}

impl<B: Binary, S: ReturnStack> Iterator for Tracer<B, S> {
    type Item = Result<Item, Error<B::Error>>;

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
            IterationState::FollowExec | IterationState::Depleting => {
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
pub struct Builder<B: Binary = binary::Empty> {
    binary: B,
    max_stack_depth: usize,
    sequentially_inferred_jumps: bool,
    address_mode: AddressMode,
    address_delta_width: core::num::NonZeroU8,
    version: Version,
}

impl Builder<binary::Empty> {
    /// Create a new builder for a [`Tracer`]
    pub fn new() -> Self {
        Default::default()
    }
}

impl<B: Binary> Builder<B> {
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
            sequentially_inferred_jumps: config.sijump_p,
            address_delta_width: config.iaddress_width_p,
            ..self
        }
    }

    /// Build the [`Tracer`] with the given [`Binary`]
    ///
    /// New builders carry an empty or [`Default`] [`Binary`]. This is usually
    /// not what you want.
    pub fn with_binary<C: Binary>(self, binary: C) -> Builder<C> {
        Builder {
            binary,
            max_stack_depth: self.max_stack_depth,
            sequentially_inferred_jumps: self.sequentially_inferred_jumps,
            address_mode: self.address_mode,
            address_delta_width: self.address_delta_width,
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

    /// Build a [`Tracer`] for the given version of the tracing specification
    ///
    /// New builders are configured for [`Version::V2`].
    pub fn with_version(self, version: Version) -> Self {
        Self { version, ..self }
    }

    /// Build the [`Tracer`]
    pub fn build<S>(self) -> Result<Tracer<B, S>, Error<B::Error>>
    where
        S: ReturnStack,
    {
        let state = state::State::new(
            S::new(self.max_stack_depth)
                .ok_or(Error::CannotConstructIrStack(self.max_stack_depth))?,
            self.sequentially_inferred_jumps,
        );
        Ok(Tracer {
            state,
            iter_state: Default::default(),
            exception_previous: false,
            binary: self.binary,
            address_mode: self.address_mode,
            address_delta_width: self.address_delta_width,
            version: self.version,
        })
    }
}

impl<B: Binary + Default> Default for Builder<B> {
    fn default() -> Self {
        Self {
            binary: Default::default(),
            max_stack_depth: Default::default(),
            sequentially_inferred_jumps: Default::default(),
            address_mode: Default::default(),
            address_delta_width: core::num::NonZeroU8::MIN,
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
        context: item::Context,
        follow_up: bool,
    },
    /// We report a context update and optionally a single follow-up item
    ContextItem {
        pc: Option<u64>,
        context: item::Context,
        follow_up: bool,
    },
    /// We follow the execution path based on the current packet's data
    FollowExec,
    /// We follow the execution path as long as it's inferable
    Depleting,
}

impl Default for IterationState {
    fn default() -> Self {
        Self::Depleting
    }
}

impl IterationState {
    /// Check whether we are currently tracing, assuming we depleted all items
    pub fn is_tracing(&self) -> bool {
        !matches!(self, Self::Depleting)
    }
}
