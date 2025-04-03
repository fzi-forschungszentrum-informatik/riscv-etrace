// Copyright (C) 2024 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

//! Implements the instruction tracing algorithm.
use crate::decoder::payload::{Payload, QualStatus, Support, Synchronization};
use crate::instruction::{self, Instruction};
use crate::types::{branch, trap};
use crate::ProtocolConfiguration;

pub mod error;
pub mod item;
pub mod stack;
mod state;

use error::Error;
use instruction::binary::{self, Binary};
use stack::ReturnStack;

/// Collects the different callbacks which report the tracing output.
pub trait ReportTrace {
    /// Called after a program counter was traced.
    fn report_pc(&mut self, _pc: u64) {}
    /// Called after a trap instruction was traced.
    fn report_epc(&mut self, _epc: u64) {}
    /// Called when an instruction was disassembled. May be called multiple times for the same
    /// address.
    fn report_instr(&mut self, _addr: u64, _instr: &Instruction) {}
    /// Called when a branch will be traced. Reports the number of branches before the branch,
    /// the branch map and if the branch will be taken.
    fn report_branch(&mut self, _branch_map: branch::Map, _taken: bool) {}
}

/// Provides the state to execute the tracing algorithm
/// and executes the user-defined report callbacks.
pub struct Tracer<'a, B: Binary, S: ReturnStack = stack::NoStack> {
    state: state::State<S>,
    iter_state: IterationState,
    report_trace: &'a mut dyn ReportTrace,
    binary: B,
    address_mode: AddressMode,
    version: Version,
}

impl<B: Binary, S: ReturnStack> Tracer<'_, B, S> {
    fn get_instr(&mut self, pc: u64) -> Result<Instruction, Error<B::Error>> {
        let instr = self
            .binary
            .get_insn(pc)
            .map_err(|e| Error::CannotGetInstruction(e, pc))?;

        self.report_trace.report_instr(pc, &instr);
        Ok(instr)
    }

    pub fn process_te_inst(&mut self, payload: &Payload) -> Result<(), Error<B::Error>> {
        self.state.stack_depth = payload.implicit_return_depth();

        if let Payload::Synchronization(sync) = payload {
            let mut trap_info = None;
            if let Synchronization::Support(sup) = sync {
                return self.process_support(sup);
            } else if let Synchronization::Context(ctx) = sync {
                if self.version != Version::V1 {
                    self.state.privilege = ctx.privilege;
                }
                return Ok(());
            } else if let Synchronization::Trap(trap) = sync {
                let epc = match trap.info.kind {
                    trap::Kind::Exception => {
                        let epc = (!trap.thaddr).then_some(trap.address);
                        let addr = self.state.exception_address(&self.binary, epc)?;
                        self.report_trace.report_epc(addr);
                        addr
                    }
                    trap::Kind::Interrupt => self.state.pc,
                };
                if !trap.thaddr {
                    return Ok(());
                }
                trap_info = Some((epc, trap.info));
            }
            self.state.inferred_address = None;
            self.state.address = payload.get_address();
            if self.state.address == 0 {
                return Err(Error::AddressIsZero);
            }
            if matches!(sync, Synchronization::Trap(_)) || !self.iter_state.is_tracing() {
                self.state.branch_map = Default::default();
            }
            let insn = self.get_instr(self.state.address)?;
            if insn
                .kind
                .and_then(instruction::Kind::branch_target)
                .is_some()
            {
                let branch = sync.branch_not_taken().ok_or(Error::WrongGetBranchType)?;
                self.state.branch_map.push_branch_taken(!branch);
            }
            if self.version != Version::V1 {
                self.state.privilege = sync.get_privilege().ok_or(Error::WrongGetPrivilegeType)?;
            }
            if matches!(sync, Synchronization::Start(_)) && self.iter_state.is_tracing() {
                self.follow_execution_path(payload, false)?
            } else {
                self.state.pc = self.state.address;
                self.state.insn = insn;
                self.report_trace.report_pc(self.state.pc);
                self.state.last_pc = self.state.pc;
                self.state.last_insn = Default::default();

                self.iter_state = IterationState::SingleItem(trap_info);
            }
            Ok(())
        } else {
            if !self.iter_state.is_tracing() {
                return Err(Error::StartOfTrace);
            }
            let mut stop_at_last_branch = false;
            if matches!(payload, Payload::Address(_)) || payload.get_branches().unwrap_or(0) != 0 {
                let address = payload.get_address();
                self.state.address = match self.address_mode {
                    AddressMode::Full => address,
                    AddressMode::Delta => self.state.address.wrapping_add(address),
                };
            }
            if let Payload::Branch(branch) = payload {
                self.state.branch_map.append(branch.branch_map);
                stop_at_last_branch = branch.address.is_none();
            }
            self.follow_execution_path(payload, stop_at_last_branch)
        }
    }

    fn process_support(&mut self, support: &Support) -> Result<(), Error<B::Error>> {
        if support.qual_status != QualStatus::NoChange {
            self.iter_state = IterationState::Depleting;

            if support.qual_status == QualStatus::EndedNtr && self.state.inferred_address.is_some()
            {
                self.state.inferred_address = Some(self.state.pc);
                self.state.stop_condition = state::StopCondition::NotInferred;

                while let Some(item) = self.state.next_item(&self.binary)? {
                    self.report_trace.report_pc(item.pc());
                }
            }
        }
        Ok(())
    }

    fn follow_execution_path(
        &mut self,
        payload: &Payload,
        stop_at_last_branch: bool,
    ) -> Result<(), Error<B::Error>> {
        use state::StopCondition;

        self.state.stop_condition = if stop_at_last_branch {
            StopCondition::LastBranch
        } else if let Some(info) = payload.get_address_info() {
            StopCondition::Address {
                notify: info.notify,
                not_updiscon: !info.updiscon,
            }
        } else {
            match self.version {
                Version::V1 => {
                    let privilege = payload
                        .get_privilege()
                        .ok_or(Error::WrongGetPrivilegeType)?;
                    StopCondition::Sync {
                        privilege: Some(privilege),
                    }
                }
                _ => StopCondition::Sync { privilege: None },
            }
        };

        while let Some(item) = self.state.next_item(&self.binary)? {
            self.report_trace.report_pc(item.pc());
        }

        Ok(())
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
    pub fn build<S>(
        self,
        report_trace: &mut dyn ReportTrace,
    ) -> Result<Tracer<'_, B, S>, Error<B::Error>>
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
        Ok(Tracer {
            state,
            iter_state: Default::default(),
            report_trace,
            binary: self.binary,
            address_mode: self.address_mode,
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
