// Copyright (C) 2024 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

//! Implements the instruction tracing algorithm.
use crate::decoder::payload::{Payload, QualStatus, Support, Synchronization, Trap};
use crate::instruction::{self, Instruction};
use crate::types::{branch, Privilege};
use crate::ProtocolConfiguration;

use core::fmt;

pub mod stack;

use instruction::binary::{self, Binary};
use stack::ReturnStack;

/// Possible errors which can occur during the tracing algorithm.
#[derive(Debug)]
pub enum Error<I> {
    /// The PC cannot be set to the address, as the address is 0.
    AddressIsZero,
    /// No starting synchronization packet was read and the tracer is still at the start of the trace.
    StartOfTrace,
    /// Some branches which should have been processed are still unprocessed. The number of
    /// unprocessed branches is given.
    UnprocessedBranches(u8),
    /// An unexpected uninferable discontinuity was encountered.
    UnexpectedUninferableDiscon,
    /// The tracer cannot resolve the branch because all branches have been processed.
    UnresolvableBranch,
    /// The current synchronization packet has no branching information.
    WrongGetBranchType,
    /// The current packet has no privilege information.
    WrongGetPrivilegeType,
    /// The IR stack cannot be constructed for the given size
    CannotConstructIrStack(usize),
    /// We could not fetch an [Instruction] from a given address
    CannotGetInstruction(I, u64),
}

impl<I> core::error::Error for Error<I>
where
    I: fmt::Debug + core::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::CannotGetInstruction(inner, _) => Some(inner),
            _ => None,
        }
    }
}

impl<I> fmt::Display for Error<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AddressIsZero => write!(f, "address is zero"),
            Self::StartOfTrace => write!(f, "expected sync packet"),
            Self::UnprocessedBranches(c) => write!(f, "{c} unprocessed branches"),
            Self::UnexpectedUninferableDiscon => write!(f, "unexpected uninferable discontinuity"),
            Self::UnresolvableBranch => write!(f, "unresolvable branch"),
            Self::WrongGetBranchType => write!(f, "expected branching info in packet"),
            Self::WrongGetPrivilegeType => write!(f, "expected privilege info in packet"),
            Self::CannotConstructIrStack(size) => {
                write!(f, "Cannot construct return stack of size {size}")
            }
            Self::CannotGetInstruction(_, addr) => {
                write!(f, "Cannot get the instruction at {addr:#0x}")
            }
        }
    }
}

/// Includes the necessary information for the tracing algorithm to trace the instruction execution.
///
/// For specifics see the pseudocode in the
/// [repository](https://github.com/riscv-non-isa/riscv-trace-spec/blob/main/referenceFlow/scripts/decoder_model.py)
/// and the specification.
#[derive(Clone, Debug)]
pub struct TraceState<S: ReturnStack> {
    pub pc: u64,
    pub last_pc: u64,
    pub address: u64,
    pub branch_map: branch::Map,
    pub stop_at_last_branch: bool,
    pub inferred_address: bool,
    pub start_of_trace: bool,
    pub privilege: Privilege,
    pub return_stack: S,
}

impl<S: ReturnStack> TraceState<S> {
    fn new(return_stack: S) -> Self {
        TraceState {
            pc: 0,
            last_pc: 0,
            branch_map: Default::default(),
            stop_at_last_branch: false,
            inferred_address: false,
            start_of_trace: true,
            address: 0,
            privilege: Privilege::User,
            return_stack,
        }
    }
}

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
    state: TraceState<S>,
    report_trace: &'a mut dyn ReportTrace,
    binary: B,
    address_mode: AddressMode,
    sequential_jumps: bool,
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

    fn incr_pc(&mut self, incr: i32) {
        self.state.pc = if incr.is_negative() {
            self.state.pc.overflowing_sub(incr.wrapping_abs() as u64).0
        } else {
            self.state.pc.overflowing_add(incr as u64).0
        }
    }

    pub fn process_te_inst(&mut self, payload: &Payload) -> Result<(), Error<B::Error>> {
        if let Payload::Synchronization(sync) = payload {
            if let Synchronization::Support(sup) = sync {
                return self.process_support(sup, payload);
            } else if let Synchronization::Context(ctx) = sync {
                if self.version != Version::V1 {
                    self.state.privilege = ctx.privilege;
                }
                return Ok(());
            } else if let Synchronization::Trap(trap) = sync {
                if !trap.interrupt {
                    let addr = self.exception_address(trap, payload)?;
                    self.report_trace.report_epc(addr);
                }
                if !trap.thaddr {
                    return Ok(());
                }
            }
            self.state.inferred_address = false;
            self.state.address = payload.get_address();
            if self.state.address == 0 {
                return Err(Error::AddressIsZero);
            }
            if matches!(sync, Synchronization::Trap(_)) || self.state.start_of_trace {
                self.state.branch_map = Default::default();
            }
            if self
                .get_instr(self.state.address)?
                .kind
                .and_then(instruction::Kind::branch_target)
                .is_some()
            {
                let branch = sync.branch_not_taken().ok_or(Error::WrongGetBranchType)?;
                self.state.branch_map.push_branch_taken(!branch);
            }
            if matches!(sync, Synchronization::Start(_)) && !self.state.start_of_trace {
                self.follow_execution_path(payload)?
            } else {
                self.state.pc = self.state.address;
                self.report_trace.report_pc(self.state.pc);
                self.state.last_pc = self.state.pc;
            }
            if self.version != Version::V1 {
                self.state.privilege = sync.get_privilege().ok_or(Error::WrongGetPrivilegeType)?;
            }
            self.state.start_of_trace = false;
            Ok(())
        } else {
            if self.state.start_of_trace {
                return Err(Error::StartOfTrace);
            }
            if matches!(payload, Payload::Address(_)) || payload.get_branches().unwrap_or(0) != 0 {
                self.state.stop_at_last_branch = false;
                let address = payload.get_address();
                self.state.address = match self.address_mode {
                    AddressMode::Full => address,
                    AddressMode::Delta => self.state.address.wrapping_add(address),
                };
            }
            if let Payload::Branch(branch) = payload {
                self.state.branch_map.append(branch.branch_map);
            }
            self.follow_execution_path(payload)
        }
    }

    fn process_support(
        &mut self,
        support: &Support,
        payload: &Payload,
    ) -> Result<(), Error<B::Error>> {
        if support.qual_status != QualStatus::NoChange {
            self.state.start_of_trace = true;

            if support.qual_status == QualStatus::EndedNtr && self.state.inferred_address {
                let local_previous_address = self.state.pc;
                self.state.inferred_address = false;
                loop {
                    let local_stop_here = self.next_pc(local_previous_address, payload)?;
                    self.report_trace.report_pc(self.state.pc);
                    if local_stop_here {
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }

    fn branch_limit(&mut self) -> Result<u8, Error<B::Error>> {
        if self
            .get_instr(self.state.pc)?
            .kind
            .and_then(instruction::Kind::branch_target)
            .is_some()
        {
            Ok(1)
        } else {
            Ok(0)
        }
    }

    fn follow_execution_path_catch_priv_changes(
        &mut self,
        payload: &Payload,
    ) -> Result<bool, Error<B::Error>> {
        let res = match self.version {
            Version::V1 => {
                let priviledge = payload
                    .get_privilege()
                    .ok_or(Error::WrongGetPrivilegeType)?;
                priviledge == self.state.privilege
                    && self
                        .get_instr(self.state.last_pc)?
                        .kind
                        .map(instruction::Kind::is_return_from_trap)
                        .unwrap_or(false)
            }
            Version::V2 => true,
        };
        Ok(res)
    }

    fn follow_execution_path(&mut self, payload: &Payload) -> Result<(), Error<B::Error>> {
        use instruction::Kind;

        let previous_address = self.state.pc;
        let mut stop_here;
        loop {
            if self.state.inferred_address {
                stop_here = self.next_pc(previous_address, payload)?;
                self.report_trace.report_pc(previous_address);
                if stop_here {
                    self.state.inferred_address = false;
                }
            } else {
                stop_here = self.next_pc(self.state.address, payload)?;
                self.report_trace.report_pc(self.state.pc);
                if self.state.branch_map.count() == 1
                    && self
                        .get_instr(self.state.pc)?
                        .kind
                        .and_then(Kind::branch_target)
                        .is_some()
                    && self.state.stop_at_last_branch
                {
                    self.state.stop_at_last_branch = true;
                    return Ok(());
                }
                if stop_here {
                    if self.state.branch_map.count() > self.branch_limit()? {
                        return Err(Error::UnprocessedBranches(self.state.branch_map.count()));
                    }
                    return Ok(());
                }
                if !matches!(payload, Payload::Synchronization(_))
                    && self.state.pc == self.state.address
                    && !self.state.stop_at_last_branch
                    && payload
                        .get_address_info()
                        .map(|a| a.notify)
                        .unwrap_or(false)
                    && self.state.branch_map.count() == self.branch_limit()?
                {
                    return Ok(());
                }
                if !matches!(payload, Payload::Synchronization(_))
                    && self.state.pc == self.state.address
                    && !self.state.stop_at_last_branch
                    && !&self
                        .get_instr(self.state.last_pc)?
                        .kind
                        .map(Kind::is_uninferable_discon)
                        .unwrap_or(false)
                    && !payload
                        .get_address_info()
                        .map(|a| a.updiscon)
                        .unwrap_or(false)
                    && self.state.branch_map.count() == self.branch_limit()?
                    && payload
                        .implicit_return_depth()
                        .map(|v| v == self.state.return_stack.depth())
                        .unwrap_or(true)
                {
                    self.state.inferred_address = true;
                    return Ok(());
                }
                if matches!(payload, Payload::Synchronization(_))
                    && self.state.pc == self.state.address
                    && self.state.branch_map.count() == self.branch_limit()?
                    && self.follow_execution_path_catch_priv_changes(payload)?
                {
                    return Ok(());
                }
            }
        }
    }

    fn next_pc(&mut self, address: u64, payload: &Payload) -> Result<bool, Error<B::Error>> {
        use instruction::Kind;

        let instr = self.get_instr(self.state.pc)?;
        let this_pc = self.state.pc;
        let mut stop_here = false;

        if let Some(target) = instr.kind.and_then(Kind::inferable_jump_target) {
            self.incr_pc(target);
            if target == 0 {
                stop_here = true;
            }
        } else if let Some(target) = self.sequential_jump_target(this_pc, self.state.last_pc)? {
            self.state.pc = target;
        } else if let Some(addr) = self.implicit_return_address(&instr, payload) {
            self.state.pc = addr;
        } else if instr.kind.map(Kind::is_uninferable_discon).unwrap_or(false) {
            if self.state.stop_at_last_branch {
                return Err(Error::UnexpectedUninferableDiscon);
            }
            self.state.pc = address;
            stop_here = true;
        } else if let Some(target) = self.taken_branch_target(&instr)? {
            self.incr_pc(target.into());
            if target == 0 {
                stop_here = true;
            }
        } else {
            self.incr_pc(instr.size as i32);
        }

        self.push_return_stack(&instr, this_pc)?;

        self.state.last_pc = this_pc;

        Ok(stop_here)
    }

    /// If the given instruction is a branch and it was taken, return its target
    ///
    /// This roughly corresponds to a combination of `is_taken_branch` of the
    /// reference implementation.
    fn taken_branch_target(&mut self, instr: &Instruction) -> Result<Option<i16>, Error<B::Error>> {
        let Some(target) = instr.kind.and_then(instruction::Kind::branch_target) else {
            // Not a branch instruction
            return Ok(None);
        };
        let taken = self
            .state
            .branch_map
            .pop_taken()
            .ok_or(Error::UnresolvableBranch)?;
        self.report_trace
            .report_branch(self.state.branch_map, taken);
        Ok(taken.then_some(target))
    }

    /// If a pair of addresses constitute a sequential jump, compute the target
    ///
    /// This roughly corresponds to a combination of `is_sequential_jump` and
    /// `sequential_jump_target` of the reference implementation.
    fn sequential_jump_target(
        &mut self,
        addr: u64,
        prev_addr: u64,
    ) -> Result<Option<u64>, Error<B::Error>> {
        use instruction::Kind;

        if !self.sequential_jumps {
            return Ok(None);
        }
        let Some(insn) = self.get_instr(addr)?.kind else {
            return Ok(None);
        };

        let target = self.get_instr(prev_addr)?.kind.and_then(|i| match i {
            Kind::auipc(d) => Some((d.rd, prev_addr.wrapping_add_signed(d.imm.into()))),
            Kind::lui(d) => Some((d.rd, d.imm as u64)),
            Kind::c_lui(d) => Some((d.rd, d.imm as u64)),
            _ => None,
        });

        let target = Option::zip(insn.uninferable_jump(), target)
            .filter(|((dep, _), (r, _))| r == dep)
            .map(|((_, off), (_, t))| t.wrapping_add_signed(off.into()));

        Ok(target)
    }

    /// If the given instruction is a function return, try to find the return address
    ///
    /// This roughly corresponds to a combination of `is_implicit_return` and
    /// `pop_return_stack` of the reference implementation.
    fn implicit_return_address(&mut self, instr: &Instruction, payload: &Payload) -> Option<u64> {
        use instruction::Kind;

        if instr.kind.map(Kind::is_return).unwrap_or(false) {
            if payload.implicit_return_depth() == Some(self.state.return_stack.depth()) {
                return None;
            }

            return self.state.return_stack.pop();
        }

        None
    }

    fn push_return_stack(&mut self, instr: &Instruction, addr: u64) -> Result<(), Error<B::Error>> {
        if !instr.kind.map(instruction::Kind::is_call).unwrap_or(false) {
            return Ok(());
        }

        let local_instr = self.get_instr(addr)?;
        self.state
            .return_stack
            .push(addr + (local_instr.size as u64));
        Ok(())
    }

    fn exception_address(
        &mut self,
        trap: &Trap,
        payload: &Payload,
    ) -> Result<u64, Error<B::Error>> {
        use instruction::Kind;

        let instr = self.get_instr(self.state.pc)?;

        if instr.kind.map(Kind::is_uninferable_discon).unwrap_or(false) && trap.thaddr {
            Ok(trap.address)
        } else if instr
            .kind
            .filter(|name| matches!(*name, Kind::ecall | Kind::ebreak | Kind::c_ebreak))
            .is_some()
        {
            Ok(self.state.pc)
        } else {
            Ok(if self.next_pc(self.state.pc, payload)? {
                self.state.pc + instr.size as u64
            } else {
                self.state.pc
            })
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

        let state = TraceState::new(
            S::new(max_stack_depth).ok_or(Error::CannotConstructIrStack(max_stack_depth))?,
        );
        Ok(Tracer {
            state,
            report_trace,
            binary: self.binary,
            address_mode: self.address_mode,
            sequential_jumps: self.config.sijump_p,
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
