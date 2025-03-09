// Copyright (C) 2024 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

//! Implements the instruction tracing algorithm.
#[cfg(feature = "implicit_return")]
use crate::decoder::payload::Extension;
use crate::decoder::payload::{Payload, Privilege, QualStatus, Support, Synchronization, Trap};
use crate::instruction::{self, Instruction, InstructionBits, Segment};
use crate::ProtocolConfiguration;

use core::fmt;

pub mod cache;

use cache::InstructionCache;

/// Possible errors which can occur during the tracing algorithm.
#[derive(Debug)]
pub enum Error {
    /// The PC cannot be set to the address, as the address is 0.
    AddressIsZero,
    /// No starting synchronization packet was read and the tracer is still at the start of the trace.
    StartOfTrace,
    /// Some branches which should have been processed are still unprocessed. The number of
    /// unprocessed branches is given.
    UnprocessedBranches(u8),
    /// The immediate of the disassembled instruction is zero but shouldn't be.
    ImmediateIsNone(Instruction),
    /// An unexpected uninferable discontinuity was encountered.
    UnexpectedUninferableDiscon,
    /// The tracer cannot resolve the branch because all branches have been processed.
    UnresolvableBranch,
    /// The current synchronization packet has no branching information.
    WrongGetBranchType,
    /// The current packet has no privilege information.
    WrongGetPrivilegeType,
    /// The instruction at `address` cannot be parsed.
    UnknownInstruction {
        address: u64,
        bytes: [u8; 4],
        segment_idx: usize,
        vaddr_start: u64,
        vaddr_end: u64,
    },
    /// The address is not inside a [Segment].
    SegmentationFault(u64),
    /// The ir stack has exceeded its allocated size.
    IrStackExhausted(u64, u64),
}

impl core::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AddressIsZero => write!(f, "address is zero"),
            Self::StartOfTrace => write!(f, "expected sync packet"),
            Self::UnprocessedBranches(c) => write!(f, "{c} unprocessed branches"),
            Self::ImmediateIsNone(_) => write!(f, "expected non-zero immediate of instruction"),
            Self::UnexpectedUninferableDiscon => write!(f, "unexpected uninferable discontinuity"),
            Self::UnresolvableBranch => write!(f, "unresolvable branch"),
            Self::WrongGetBranchType => write!(f, "expected branching info in packet"),
            Self::WrongGetPrivilegeType => write!(f, "expected privilege info in packet"),
            Self::UnknownInstruction {
                address,
                bytes,
                segment_idx,
                vaddr_start,
                vaddr_end,
            } => {
                let bytes = u32::from_be_bytes(*bytes);
                write!(f, "unknown instruction {bytes:x} at {address:#0x}")?;
                write!(
                    f,
                    ", segment: {segment_idx} ({vaddr_start:#0x}, {vaddr_end:#0x})"
                )
            }
            Self::SegmentationFault(addr) => {
                write!(f, "address {addr:#0x} not in any known segment")
            }
            Self::IrStackExhausted(size, supremum) => {
                write!(
                    f,
                    "IR stack has grown to {size}, which is greater than the allocated {supremum}",
                )
            }
        }
    }
}

/// Configuration used only by the tracer.
#[derive(Copy, Clone, Debug)]
pub struct TraceConfiguration<'a> {
    /// The memory segments which will be traced. It is assumed the segments **do not overlap**
    /// with each other.
    pub segments: &'a [Segment<'a>],
    pub full_address: bool,
}

/// Supremum of depth of the implicit return stack.
/// This value should **always** be larger than the maximum ir stack depth.
pub const IRSTACK_DEPTH_SUPREMUM: u64 = 32;

/// Includes the necessary information for the tracing algorithm to trace the instruction execution.
///
/// For specifics see the pseudocode in the
/// [repository](https://github.com/riscv-non-isa/riscv-trace-spec/blob/main/referenceFlow/scripts/decoder_model.py)
/// and the specification.
#[derive(Clone)]
pub struct TraceState<C: InstructionCache> {
    pub pc: u64,
    pub last_pc: u64,
    pub address: u64,
    pub branches: u8,
    // u32 because there can be a maximum of 31 branches.
    pub branch_map: u32,
    pub stop_at_last_branch: bool,
    pub inferred_address: bool,
    pub start_of_trace: bool,
    pub notify: bool,
    pub updiscon: bool,
    pub ir: bool,
    pub privilege: Privilege,
    pub return_stack: [u64; 32],
    pub irstack_depth: u64,
    pub segment_idx: usize,
    pub instr_cache: C,
}

impl<C: InstructionCache + Default> TraceState<C> {
    fn default() -> Self {
        TraceState {
            pc: 0,
            last_pc: 0,
            branches: 0,
            branch_map: 0,
            stop_at_last_branch: false,
            inferred_address: false,
            start_of_trace: true,
            address: 0,
            notify: false,
            updiscon: false,
            ir: false,
            privilege: Privilege::User,
            return_stack: [0; IRSTACK_DEPTH_SUPREMUM as usize],
            irstack_depth: 0,
            segment_idx: 0,
            instr_cache: Default::default(),
        }
    }
}

impl<C: InstructionCache + fmt::Debug> fmt::Debug for TraceState<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_fmt(format_args!(
            "TracerState {{ pc: {:#0x}, last_pc: {:#0x}, address: {:#0x}, \
        branches: {}, branch_map: 0b{:b}, stop_at_last_branch: {}, \
        inferred_address: {}, start_of_trace: {}, notify: {}, \
        updiscon: {}, privilege: {:?}, segment_idx: {} }}",
            self.pc,
            self.last_pc,
            self.address,
            self.branches,
            self.branch_map,
            self.stop_at_last_branch,
            self.inferred_address,
            self.start_of_trace,
            self.notify,
            self.updiscon,
            self.privilege,
            self.segment_idx,
        ))
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
    fn report_branch(&mut self, _branches: u8, _branch_map: u32, _taken: bool) {}
}

/// Provides the state to execute the tracing algorithm
/// and executes the user-defined report callbacks.
pub struct Tracer<'a, C: InstructionCache = cache::NoCache> {
    state: TraceState<C>,
    proto_conf: ProtocolConfiguration,
    trace_conf: TraceConfiguration<'a>,
    report_trace: &'a mut dyn ReportTrace,
}

impl<'a, C: InstructionCache + Default> Tracer<'a, C> {
    pub fn new(
        proto_conf: ProtocolConfiguration,
        trace_conf: TraceConfiguration<'a>,
        report_trace: &'a mut dyn ReportTrace,
    ) -> Self {
        Tracer {
            state: TraceState::default(),
            trace_conf,
            proto_conf,
            report_trace,
        }
    }

    fn get_instr(&mut self, pc: u64) -> Result<Instruction, Error> {
        if !self.trace_conf.segments[self.state.segment_idx].contains(pc) {
            let old = self.state.segment_idx;
            for i in 0..self.trace_conf.segments.len() {
                if self.trace_conf.segments[i].contains(pc) {
                    self.state.segment_idx = i;
                    break;
                }
            }
            // The segment index should now point to the segment which contains the pc.
            if old == self.state.segment_idx {
                return Err(Error::SegmentationFault(pc));
            }
        }
        if let Some(instr) = self.state.instr_cache.get(pc) {
            return Ok(instr);
        }
        let binary = match InstructionBits::read_binary(
            pc,
            &self.trace_conf.segments[self.state.segment_idx],
        ) {
            Ok(binary) => binary,
            Err(bytes) => {
                return Err(Error::UnknownInstruction {
                    address: pc,
                    bytes,
                    segment_idx: self.state.segment_idx,
                    vaddr_start: self.trace_conf.segments[self.state.segment_idx].first_addr,
                    vaddr_end: self.trace_conf.segments[self.state.segment_idx].last_addr,
                })
            }
        };

        let instr = Instruction::from_binary(&binary);
        self.report_trace.report_instr(pc, &instr);
        self.state.instr_cache.store(pc, instr);
        Ok(instr)
    }

    fn incr_pc(&mut self, incr: i32) {
        self.state.pc = if incr.is_negative() {
            self.state.pc.overflowing_sub(incr.wrapping_abs() as u64).0
        } else {
            self.state.pc.overflowing_add(incr as u64).0
        }
    }

    #[cfg(not(feature = "implicit_return"))]
    fn recover_ir_status(&self, _: &Payload) -> bool {
        false
    }

    #[cfg(feature = "implicit_return")]
    fn recover_ir_status(&self, payload: &Payload) -> bool {
        return if let Some(addr) = payload.get_address_info() {
            addr.ir.irreport
        } else if let Payload::Extension(ext) = payload {
            match ext {
                Extension::BranchCount(bc) => {
                    if let Some(addr) = bc.address {
                        addr.ir.irreport
                    } else {
                        false
                    }
                }
                Extension::JumpTargetIndex(jti) => jti.ir.irreport,
            }
        } else {
            false
        };
    }

    fn recover_status_fields(&mut self, payload: &Payload) {
        if let Some(addr) = payload.get_address_info() {
            self.state.notify = addr.notify;
            self.state.updiscon = addr.updiscon;
            self.state.ir = self.recover_ir_status(payload);
        }
    }

    pub fn process_te_inst(&mut self, payload: &Payload) -> Result<(), Error> {
        self.recover_status_fields(payload);
        self._process_te_inst(payload)
    }

    fn _process_te_inst(&mut self, payload: &Payload) -> Result<(), Error> {
        if let Payload::Synchronization(sync) = payload {
            if let Synchronization::Support(sup) = sync {
                return self.process_support(sup, payload);
            } else if let Synchronization::Context(ctx) = sync {
                if cfg!(not(feature = "tracing_v1")) {
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
                self.state.branches = 0;
                self.state.branch_map = 0;
            }
            if self.get_instr(self.state.address)?.is_branch {
                let branch = sync.get_branch()?;
                self.state.branch_map |= branch << self.state.branches;
                self.state.branches += 1;
            }
            if matches!(sync, Synchronization::Start(_)) && !self.state.start_of_trace {
                self.follow_execution_path(payload)?
            } else {
                self.state.pc = self.state.address;
                self.report_trace.report_pc(self.state.pc);
                self.state.last_pc = self.state.pc;
            }
            if cfg!(not(feature = "tracing_v1")) {
                self.state.privilege = *sync.get_privilege()?;
            }
            self.state.start_of_trace = false;
            if cfg!(feature = "implicit_return") {
                self.state.irstack_depth = 0;
            }
            Ok(())
        } else {
            if self.state.start_of_trace {
                return Err(Error::StartOfTrace);
            }
            if matches!(payload, Payload::Address(_)) || payload.get_branches().unwrap_or(0) != 0 {
                self.state.stop_at_last_branch = false;
                if self.trace_conf.full_address {
                    self.state.address = payload.get_address();
                } else {
                    let addr = payload.get_address() as i64;
                    self.state.address = if addr.is_negative() {
                        self.state
                            .address
                            .overflowing_sub(addr.wrapping_abs() as u64)
                            .0
                    } else {
                        self.state.address.overflowing_add(addr as u64).0
                    };
                }
            }
            if let Payload::Branch(branch) = payload {
                self.state.stop_at_last_branch = branch.branches == 0;
                self.state.branch_map |= (branch.branch_map) << self.state.branches;
                self.state.branches += if branch.branches == 0 {
                    31
                } else {
                    branch.branches
                };
            }
            self.follow_execution_path(payload)
        }
    }

    fn process_support(&mut self, support: &Support, payload: &Payload) -> Result<(), Error> {
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

    fn branch_limit(&mut self) -> Result<u8, Error> {
        Ok(self.get_instr(self.state.pc)?.is_branch as u8)
    }

    #[cfg(feature = "implicit_return")]
    fn follow_execution_path_ir_state(&self, payload: &Payload) -> bool {
        self.state.ir || payload.implicit_return_depth() == Some(self.state.irstack_depth as usize)
    }

    #[cfg(not(feature = "implicit_return"))]
    fn follow_execution_path_ir_state(&self, _: &Payload) -> bool {
        true
    }

    #[cfg(not(feature = "tracing_v1"))]
    fn follow_execution_path_catch_priv_changes(
        &mut self,
        payload: &Payload,
    ) -> Result<bool, Error> {
        Ok(*payload.get_privilege()? == self.state.privilege
            && self.get_instr(self.state.last_pc)?.is_return_from_trap())
    }

    #[cfg(feature = "tracing_v1")]
    fn follow_execution_path_catch_priv_changes(&mut self, _: &Payload) -> Result<bool, Error> {
        Ok(true)
    }

    fn follow_execution_path(&mut self, payload: &Payload) -> Result<(), Error> {
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
                if self.state.branches == 1
                    && self.get_instr(self.state.pc)?.is_branch
                    && self.state.stop_at_last_branch
                {
                    self.state.stop_at_last_branch = true;
                    return Ok(());
                }
                if stop_here {
                    if self.state.branches > self.branch_limit()? {
                        return Err(Error::UnprocessedBranches(self.state.branches));
                    }
                    return Ok(());
                }
                if !matches!(payload, Payload::Synchronization(_))
                    && self.state.pc == self.state.address
                    && !self.state.stop_at_last_branch
                    && self.state.notify
                    && self.state.branches == self.branch_limit()?
                {
                    return Ok(());
                }
                if !matches!(payload, Payload::Synchronization(_))
                    && self.state.pc == self.state.address
                    && !self.state.stop_at_last_branch
                    && !&self.get_instr(self.state.last_pc)?.is_uninferable_discon()
                    && !self.state.updiscon
                    && self.state.branches == self.branch_limit()?
                    && self.follow_execution_path_ir_state(payload)
                {
                    self.state.inferred_address = true;
                    return Ok(());
                }
                if matches!(payload, Payload::Synchronization(_))
                    && self.state.pc == self.state.address
                    && self.state.branches == self.branch_limit()?
                    && self.follow_execution_path_catch_priv_changes(payload)?
                {
                    return Ok(());
                }
            }
        }
    }

    fn next_pc(&mut self, address: u64, payload: &Payload) -> Result<bool, Error> {
        let instr = self.get_instr(self.state.pc)?;
        let this_pc = self.state.pc;
        let mut stop_here = false;

        if instr.is_inferable_jump() {
            let imm = instr.imm.ok_or(Error::ImmediateIsNone(instr))?;
            self.incr_pc(imm);
            if imm == 0 {
                stop_here = true;
            }
        } else if self.is_sequential_jump(&instr, self.state.last_pc)? {
            self.state.pc = self.sequential_jump_target(self.state.pc, self.state.last_pc)?;
        } else if self.is_implicit_return(&instr, payload) {
            self.state.pc = self.pop_return_stack();
        } else if instr.is_uninferable_discon() {
            if self.state.stop_at_last_branch {
                return Err(Error::UnexpectedUninferableDiscon);
            }
            self.state.pc = address;
            stop_here = true;
        } else if self.is_taken_branch(&instr)? {
            let imm = instr.imm.ok_or(Error::ImmediateIsNone(instr))?;
            self.incr_pc(imm);
            if imm == 0 {
                stop_here = true;
            }
        } else {
            self.incr_pc(instr.size as i32);
        }

        self.push_return_stack(&instr, this_pc)?;

        self.state.last_pc = this_pc;

        Ok(stop_here)
    }

    #[allow(clippy::wrong_self_convention)]
    fn is_taken_branch(&mut self, instr: &Instruction) -> Result<bool, Error> {
        if !instr.is_branch {
            return Ok(false);
        }
        if self.state.branches == 0 {
            return Err(Error::UnresolvableBranch);
        }
        let taken = self.state.branch_map & 1 == 0;
        self.report_trace
            .report_branch(self.state.branches, self.state.branch_map, taken);
        self.state.branches -= 1;
        self.state.branch_map >>= 1;
        Ok(taken)
    }

    #[cfg(not(feature = "implicit_return"))]
    #[allow(clippy::wrong_self_convention)]
    pub fn is_sequential_jump(&mut self, _: &Instruction, _: u64) -> Result<bool, Error> {
        Ok(false)
    }

    #[cfg(feature = "implicit_return")]
    #[allow(clippy::wrong_self_convention)]
    pub fn is_sequential_jump(
        &mut self,
        instr: &Instruction,
        prev_addr: u64,
    ) -> Result<bool, Error> {
        use instruction::Kind;

        if !(instr.is_uninferable_jump() && self.proto_conf.sijump_p) {
            return Ok(false);
        }

        let prev_instr = self.get_instr(prev_addr)?;

        if prev_instr
            .kind
            .filter(|name| matches!(*name, Kind::auipc(_) | Kind::lui(_) | Kind::c_lui(_)))
            .is_some()
        {
            return Ok(instr.rs1 == prev_instr.rd);
        }
        Ok(false)
    }

    #[cfg(not(feature = "implicit_return"))]
    fn sequential_jump_target(&mut self, _: u64, _: u64) -> Result<u64, Error> {
        unreachable!()
    }

    #[cfg(feature = "implicit_return")]
    fn sequential_jump_target(&mut self, addr: u64, prev_addr: u64) -> Result<u64, Error> {
        use instruction::Kind;

        let instr = self.get_instr(addr)?;
        let prev_instr = self.get_instr(prev_addr)?;
        let mut target = 0;

        if matches!(prev_instr.kind, Some(Kind::auipc(_))) {
            target = prev_addr;
        }
        let imm = prev_instr.imm.ok_or(Error::ImmediateIsNone(prev_instr))?;
        if imm.is_negative() {
            target = target.overflowing_sub(imm.abs() as u64).0
        } else {
            target = target.overflowing_add(imm as u64).0;
        }
        if matches!(instr.kind, Some(Kind::jalr(_))) {
            if imm.is_negative() {
                target = target.overflowing_sub(imm.abs() as u64).0
            } else {
                target = target.overflowing_add(imm as u64).0;
            }
        }
        Ok(target)
    }

    #[cfg(not(feature = "implicit_return"))]
    fn is_implicit_return(&self, _: &Instruction, _: &Payload) -> bool {
        false
    }

    #[cfg(feature = "implicit_return")]
    fn is_implicit_return(&self, instr: &Instruction, payload: &Payload) -> bool {
        use instruction::format::{TypeI, TypeR};
        use instruction::Kind;

        if let Some(name) = instr.kind {
            if matches!(
                name,
                Kind::jalr(TypeI { rd: 0, rs1: 1, .. }) | Kind::c_jr(TypeR { rs1: 1, .. })
            ) {
                if self.state.ir
                    && payload.implicit_return_depth() == Some(self.state.irstack_depth as usize)
                {
                    return false;
                }
                return self.state.irstack_depth > 0;
            }
        }
        return false;
    }

    #[cfg(not(feature = "implicit_return"))]
    fn push_return_stack(&mut self, _: &Instruction, _: u64) -> Result<(), Error> {
        Ok(())
    }

    #[cfg(feature = "implicit_return")]
    fn push_return_stack(&mut self, instr: &Instruction, addr: u64) -> Result<(), Error> {
        if !instr.is_call() {
            return Ok(());
        }

        let local_instr = self.get_instr(addr)?;
        let mut link = addr;

        let irstack_depth_max = if self.proto_conf.return_stack_size_p != 0 {
            2_u64.pow(self.proto_conf.return_stack_size_p.into())
        } else {
            2_u64.pow(self.proto_conf.call_counter_size_p.into())
        };

        if irstack_depth_max > IRSTACK_DEPTH_SUPREMUM {
            return Err(Error::IrStackExhausted(
                irstack_depth_max,
                IRSTACK_DEPTH_SUPREMUM,
            ));
        }

        if self.state.irstack_depth == irstack_depth_max {
            self.state.irstack_depth -= 1;
            for i in 0..irstack_depth_max {
                self.state.return_stack[i as usize] = self.state.return_stack[i as usize + 1];
            }
        }

        link += (local_instr.size as u64) * 8;

        self.state.return_stack[self.state.irstack_depth as usize] = link;
        self.state.irstack_depth += 1;

        Ok(())
    }

    #[cfg(not(feature = "implicit_return"))]
    fn pop_return_stack(&mut self) -> u64 {
        unreachable!()
    }

    #[cfg(feature = "implicit_return")]
    fn pop_return_stack(&mut self) -> u64 {
        self.state.irstack_depth -= 1;
        self.state.return_stack[self.state.irstack_depth as usize]
    }

    fn exception_address(&mut self, trap: &Trap, payload: &Payload) -> Result<u64, Error> {
        use instruction::Kind;

        let instr = self.get_instr(self.state.pc)?;

        if instr.is_uninferable_discon() && trap.thaddr {
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
