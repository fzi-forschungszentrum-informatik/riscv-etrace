// Copyright (C) 2024 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

//! Implements the instruction tracing algorithm.
use crate::decoder::payload::{self, Payload, QualStatus, Support, Synchronization};
use crate::instruction;
use crate::types::trap;
use crate::ProtocolConfiguration;

pub mod error;
pub mod item;
pub mod stack;
mod state;

#[cfg(test)]
mod tests;

use error::Error;
use instruction::binary::{self, Binary};
use stack::ReturnStack;

/// Provides the state to execute the tracing algorithm
/// and executes the user-defined report callbacks.
pub struct Tracer<B: Binary, S: ReturnStack = stack::NoStack> {
    state: state::State<S>,
    iter_state: IterationState,
    binary: B,
    address_delta_width: Option<u8>,
    version: Version,
}

impl<B: Binary, S: ReturnStack> Tracer<B, S> {
    pub fn process_te_inst(&mut self, payload: &Payload) -> Result<(), Error<B::Error>> {
        use state::StopCondition;

        if !self.state.is_fused() {
            return Err(Error::UnprocessedInstructions);
        }

        if let Payload::Synchronization(sync) = payload {
            self.process_sync(sync)
        } else {
            self.state.stack_depth = payload.implicit_return_depth();

            if !self.iter_state.is_tracing() {
                return Err(Error::StartOfTrace);
            }
            if let Payload::Branch(branch) = payload {
                self.state.branch_map.append(branch.branch_map);
            }
            if let Some(info) = payload.get_address_info() {
                let mut address = info.address;
                self.state.address = if let Some(width) = self.address_delta_width {
                    if address >> width.saturating_sub(1) != 0 {
                        address |= u64::MAX.checked_shl(width.into()).unwrap_or(0);
                    }
                    self.state.address.wrapping_add(address)
                } else {
                    address
                };

                self.state.stop_condition = StopCondition::Address {
                    notify: info.notify,
                    not_updiscon: !info.updiscon,
                };
            } else {
                self.state.stop_condition = StopCondition::LastBranch;
            }
            Ok(())
        }
    }

    /// Process a [payload::Synchronization]
    fn process_sync(&mut self, sync: &payload::Synchronization) -> Result<(), Error<B::Error>> {
        use payload::Synchronization;

        let mut trap_info = None;
        match sync {
            Synchronization::Start(start) => {
                self.sync_init(
                    start.address,
                    !self.iter_state.is_tracing(),
                    !start.branch,
                    &start.ctx,
                )?;

                if self.iter_state.is_tracing() {
                    let privilege = match self.version {
                        Version::V1 => Some(start.ctx.privilege),
                        _ => None,
                    };
                    self.state.stop_condition = state::StopCondition::Sync { privilege };
                    return Ok(());
                }
            }
            Synchronization::Trap(trap) => {
                let epc = match trap.info.kind {
                    trap::Kind::Exception => {
                        let epc = (!trap.thaddr).then_some(trap.address);
                        self.state.exception_address(&self.binary, epc)?
                    }
                    trap::Kind::Interrupt => self.state.pc,
                };
                if !trap.thaddr {
                    return Ok(());
                }
                trap_info = Some((epc, trap.info));

                self.sync_init(trap.address, false, !trap.branch, &trap.ctx)?;
            }
            Synchronization::Context(ctx) => {
                self.state.stack_depth = None;
                if self.version != Version::V1 {
                    self.state.privilege = ctx.privilege;
                }
                return Ok(());
            }
            Synchronization::Support(sup) => {
                return self.process_support(sup);
            }
        }

        let insn = self
            .binary
            .get_insn(self.state.address)
            .map_err(|e| Error::CannotGetInstruction(e, self.state.address))?;
        self.state.pc = self.state.address;
        self.state.insn = insn;
        self.state.last_pc = self.state.pc;
        self.state.last_insn = Default::default();

        self.iter_state = IterationState::SingleItem(trap_info);
        Ok(())
    }

    fn process_support(&mut self, support: &Support) -> Result<(), Error<B::Error>> {
        self.state.stack_depth = None;
        if support.qual_status != QualStatus::NoChange {
            self.iter_state = IterationState::Depleting;

            if support.qual_status == QualStatus::EndedNtr && self.state.inferred_address.is_some()
            {
                self.state.inferred_address = Some(self.state.pc);
                self.state.stop_condition = state::StopCondition::NotInferred;
            }
        }
        Ok(())
    }

    /// Perform initialization for processing of some [Synchronization] variants
    fn sync_init(
        &mut self,
        address: u64,
        reset_branch_map: bool,
        branch_taken: bool,
        ctx: &payload::Context,
    ) -> Result<(), Error<B::Error>> {
        let insn = self
            .binary
            .get_insn(address)
            .map_err(|e| Error::CannotGetInstruction(e, address))?;

        self.state.address = address;
        self.state.inferred_address = None;

        if reset_branch_map {
            self.state.branch_map = Default::default();
        }
        if insn
            .kind
            .and_then(instruction::Kind::branch_target)
            .is_some()
        {
            self.state.branch_map.push_branch_taken(branch_taken);
        }

        if self.version != Version::V1 {
            self.state.privilege = ctx.privilege;
        }

        self.state.stack_depth = None;

        Ok(())
    }
}

impl<B: Binary, S: ReturnStack> Iterator for Tracer<B, S> {
    type Item = Result<item::Item, Error<B::Error>>;

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
                self.state.next_item(&self.binary).transpose()
            }
        }
    }
}

/// Builder for [Tracer]
#[derive(Copy, Clone, Default)]
pub struct Builder<B: Binary = binary::Empty> {
    config: ProtocolConfiguration,
    binary: B,
    address_mode: AddressMode,
    version: Version,
}

impl Builder<binary::Empty> {
    /// Create a new builder for a [Tracer]
    pub fn new() -> Self {
        Default::default()
    }
}

impl<B: Binary> Builder<B> {
    /// Build the [Tracer] for the given [ProtocolConfiguration]
    ///
    /// New builders carry a [Default] configuration.
    pub fn with_config(self, config: ProtocolConfiguration) -> Self {
        Self { config, ..self }
    }

    /// Build the [Tracer] with the given [Binary]
    ///
    /// New builders carry an empty or [Default] [Binary]. This is usually not
    /// what you want.
    pub fn with_binary<C: Binary>(self, binary: C) -> Builder<C> {
        Builder {
            config: self.config,
            binary,
            address_mode: self.address_mode,
            version: self.version,
        }
    }

    /// Build a [Tracer] for the given [AddressMode]
    ///
    /// New builders are configured for [AddressMode::Delta].
    pub fn with_address_mode(self, mode: AddressMode) -> Self {
        Self {
            address_mode: mode,
            ..self
        }
    }

    /// Build a [Tracer] for the given version of the tracing specification
    ///
    /// New builders are configured for [Version::V2].
    pub fn with_version(self, version: Version) -> Self {
        Self { version, ..self }
    }

    /// Build the [Tracer] with the given reporter
    pub fn build<S>(self) -> Result<Tracer<B, S>, Error<B::Error>>
    where
        S: ReturnStack,
    {
        let max_stack_depth = if self.config.return_stack_size_p > 0 {
            1 << self.config.return_stack_size_p
        } else if self.config.call_counter_size_p > 0 {
            1 << self.config.call_counter_size_p
        } else {
            0
        };

        let state = state::State::new(
            S::new(max_stack_depth).ok_or(Error::CannotConstructIrStack(max_stack_depth))?,
            self.config.sijump_p,
        );
        let address_delta_width = match self.address_mode {
            AddressMode::Full => None,
            AddressMode::Delta => Some(self.config.iaddress_width_p),
        };
        Ok(Tracer {
            state,
            iter_state: Default::default(),
            binary: self.binary,
            address_delta_width,
            version: self.version,
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Version {
    V1,
    V2,
}

impl Default for Version {
    fn default() -> Self {
        Self::V2
    }
}

/// Address mode
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AddressMode {
    /// Any addresses is assumed to be a full, absolute addresses
    Full,
    /// An addresses is assumed to be relative to the previous address
    Delta,
}

impl Default for AddressMode {
    fn default() -> Self {
        Self::Delta
    }
}

/// [Tracer] iteration states
#[derive(Copy, Clone, Debug)]
enum IterationState {
    /// The [Tracer] reports a single item
    ///
    /// We know about exactly one item we report, which may have an EPC and
    /// [trap::Info] associated with it. We don't have any information beyond
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
    pub fn is_tracing(&self) -> bool {
        !matches!(self, Self::Depleting)
    }
}
