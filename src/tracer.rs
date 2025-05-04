// Copyright (C) 2024, 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Tracing logic
//!
//! This module provides the [`Tracer`], which processes tracing packet
//! [`Payload`]s and generates streams of tracing [`Item`]s.

pub mod error;
pub mod item;
pub mod stack;
mod state;

#[cfg(test)]
mod tests;

pub use item::Item;

use crate::config::{self, AddressMode, Version};
use crate::decoder::payload::Payload;
use crate::decoder::sync;
use crate::decoder::unit::IOptions;
use crate::instruction;
use crate::types::trap;

use error::Error;
use instruction::binary::{self, Binary};
use stack::ReturnStack;

/// Tracer
///
/// A tracer processes packet [`Payload`]s for a single RISC-V hart and
/// generates [`Item`]s for that hart.
///
/// [`Payload`]s are fed through [`process_te_inst`][Self::process_te_inst].
/// Alternatively, some specialized paylaods may be fed through more specialized
/// fns. After a payload was fed to the tracer, [`Item`]s become availible via
/// the tracer's [`Iterator`] implementation.
///
/// After all [`Item`]s were extracted, the next payload may be fed to the
/// tracer. Feeding a payload while the items generated from the last payload
/// are not exhaused results in an error.
///
/// # Example
///
/// The following example demonstrates feeding a [`Payload`] to a tracer and
/// then iterating over the generated [`Item`]s.
///
/// ```
/// use riscv_etrace::tracer;
///
/// # use riscv_etrace::instruction::COMPRESSED;
/// # let code: &[(u64, _)] = &[(0x28, COMPRESSED)];
/// let parameters = Default::default();
/// let mut tracer: tracer::Tracer<_> = tracer::builder()
///     .with_binary(code)
///     .with_params(&parameters)
///     .build()
///     .unwrap();
///
/// # use riscv_etrace::decoder;
/// # use decoder::payload::Payload;
/// # let payload: Payload = decoder::sync::Start {
/// #   branch: false,
/// #   ctx: Default::default(),
/// #   address: 0x28,
/// # }
/// # .into();
/// tracer.process_te_inst(&payload).unwrap();
/// tracer.by_ref().for_each(|i| {
///     println!("PC: {:0x}", i.unwrap().pc());
/// });
/// ```
pub struct Tracer<B: Binary, S: ReturnStack = stack::NoStack> {
    state: state::State<S>,
    iter_state: IterationState,
    binary: B,
    address_mode: AddressMode,
    address_delta_width: core::num::NonZeroU8,
    version: Version,
}

impl<B: Binary, S: ReturnStack> Tracer<B, S> {
    /// Process a [`Payload`]
    ///
    /// The tracer will yield new trace [`Item`]s after receiving most types of
    /// payloads via this fn.
    pub fn process_te_inst(
        &mut self,
        payload: &Payload<impl IOptions>,
    ) -> Result<(), Error<B::Error>> {
        use state::StopCondition;

        if let Payload::Synchronization(sync) = payload {
            self.process_sync(sync)
        } else {
            let mut initer = self.state.initializer(&mut self.binary)?;
            initer.set_stack_depth(payload.implicit_return_depth());

            if let Payload::Branch(branch) = payload {
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
    pub fn process_sync(
        &mut self,
        sync: &sync::Synchronization<impl IOptions>,
    ) -> Result<(), Error<B::Error>> {
        use sync::Synchronization;

        match sync {
            Synchronization::Start(start) => {
                let is_tracing = self.iter_state.is_tracing();
                let version = self.version;

                let initer = self.sync_init(
                    start.address,
                    !self.iter_state.is_tracing(),
                    !start.branch,
                    &start.ctx,
                )?;

                if is_tracing {
                    let privilege = match version {
                        Version::V1 => Some(start.ctx.privilege),
                        _ => None,
                    };
                    initer.set_condition(state::StopCondition::Sync { privilege });
                } else {
                    initer.reset_to_address()?;
                    self.iter_state = IterationState::SingleItem(None);
                }
            }
            Synchronization::Trap(trap) => {
                let epc = if trap.info.is_exception() {
                    let epc = (!trap.thaddr).then_some(trap.address);
                    self.state.exception_address(&mut self.binary, epc)?
                } else {
                    self.state.current_item().pc()
                };
                if !trap.thaddr {
                    self.state
                        .initializer(&mut self.binary)?
                        .set_stack_depth(None);
                } else {
                    self.sync_init(trap.address, false, !trap.branch, &trap.ctx)?
                        .reset_to_address()?;
                    self.iter_state = IterationState::SingleItem(Some((epc, trap.info)));
                }
            }
            Synchronization::Context(ctx) => {
                let mut initer = self.state.initializer(&mut self.binary)?;
                initer.set_stack_depth(None);
                if self.version != Version::V1 {
                    initer.set_privilege(ctx.privilege);
                }
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
    pub fn process_support(
        &mut self,
        support: &sync::Support<impl IOptions>,
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
        ctx: &sync::Context,
    ) -> Result<state::Initializer<S, B>, Error<B::Error>> {
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

        if self.version != Version::V1 {
            initer.set_privilege(ctx.privilege);
        }

        initer.set_stack_depth(None);

        Ok(initer)
    }
}

impl<B: Binary, S: ReturnStack> Iterator for Tracer<B, S> {
    type Item = Result<Item, Error<B::Error>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter_state {
            IterationState::SingleItem(trap) => {
                self.iter_state = IterationState::FollowExec;

                let item = self.state.current_item();
                let item = if let Some((epc, info)) = trap {
                    item.with_trap(epc, info)
                } else {
                    item
                };
                Some(Ok(item))
            }
            IterationState::FollowExec | IterationState::Depleting => {
                self.state.next_item(&mut self.binary).transpose()
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
    /// The [`Tracer`] reports a single item
    ///
    /// We know about exactly one item we report, which may have an EPC and
    /// [`trap::Info`] associated with it. We don't have any information beyond
    /// this item (yet).
    SingleItem(Option<(u64, trap::Info)>),
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
