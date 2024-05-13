//! Implements the instruction tracing algorithm version 2.0.1
use crate::decoder::payload::{Payload, QualStatus, Support, Synchronization, Trap};
use crate::disassembler::Name::{c_ebreak, ebreak, ecall};
use crate::disassembler::{BinaryInstruction, Instruction};
use crate::segment::Segment;
use crate::{ProtocolConfiguration, TraceConfiguration};
use core::fmt;

/// [TraceError] captures the tracing algorithm error and adds the current [TraceState]
/// in which the underlying error occured.
#[derive(Debug)]
pub struct TraceError {
    pub state: TraceState,
    pub error_type: TraceErrorType,
}

pub enum TraceErrorType {
    /// The PC cannot be set to the address, as the address is 0.
    AddressIsZero,
    /// No starting synchronization packet was read and the tracer is still at the start of the trace.
    StartOfTrace,
    /// Some branches which should have been processed are still unprocessed. The number of
    /// unprocessed branches is given.
    UnprocessedBranches(usize),
    /// The immediate of the disassembled instruction is zero but shouldn't be.
    ImmediateIsNone(Instruction),
    /// An unexpected uninferable discontinuity was encountered.
    UnexpectedUninferableDiscon,
    /// The tracer cannot resolve the branch because all branches have been processed.
    UnresolvableBranch,
    /// The processed packet has no branching information.
    WrongGetBranchType(Synchronization),
    /// The processed packet has no privilege information.
    WrongGetPrivilegeType,
    /// The instruction at the `address` cannot be parsed.
    UnknownInstruction {
        address: u64,
        value: u64,
        truncated: u32,
        segment: Segment,
    },
    /// The address is not inside a [Segment].
    SegmentationFault(u64),
}

impl fmt::Debug for TraceErrorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraceErrorType::AddressIsZero => f.write_str("AddressIsZero"),
            TraceErrorType::StartOfTrace => f.write_str("StartOfTrace"),
            TraceErrorType::UnprocessedBranches(count) => f.write_fmt(format_args!("UnprocessedBranches({})", count)),
            TraceErrorType::ImmediateIsNone(instr) => f.write_fmt(format_args!("ImmediateIsNone({:?})", instr)),
            TraceErrorType::UnexpectedUninferableDiscon => f.write_str("UnexpectedUninferableDiscon"),
            TraceErrorType::UnresolvableBranch => f.write_str("UnresolvableBranch"),
            TraceErrorType::WrongGetBranchType(sync) => f.write_fmt(format_args!("WrongGetBranchType({:?})", sync)),
            TraceErrorType::WrongGetPrivilegeType => f.write_str("WrongGetPrivilegeType"),
            TraceErrorType::UnknownInstruction {address, value, truncated, segment} =>
                f.write_fmt(format_args!("UnknownInstruction {{ address: {:#0x}, value: {:#0x}, truncated: {:#0x}, segment: {:?} }}",
                                         address,
                                         value,
                                         truncated,
                                         segment)),
            TraceErrorType::SegmentationFault(addr) => f.write_fmt(format_args!("SegmentationFault({:#0x})", addr)),
        }
    }
}

/// TracerState captures all necessary information for the tracing algorithm to trace the
/// the instruction execution.
///
/// For specifics see either the pseudo code in the
/// [repository](https://github.com/riscv-non-isa/riscv-trace-spec/blob/main/referenceFlow/scripts/decoder_model.py)
/// and the specification.
#[derive(Copy, Clone)]
pub struct TraceState {
    pc: u64,
    last_pc: u64,
    address: u64,
    branches: usize,
    branch_map: u32,
    stop_at_last_branch: bool,
    inferred_address: bool,
    start_of_trace: bool,
    notify: bool,
    updiscon: bool,
    privilege: u64,
}

impl fmt::Debug for TraceState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::result::Result<(), core::fmt::Error> {
        f.write_fmt(format_args!(
            "TracerState {{ pc: {:#0x}, last_pc: {:#0x}, address: {:#0x}, \
        branches: {}, branch_map: {}, stop_at_last_branch: {},\
        inferred_address: {}, start_of_trace: {}, notify: {}, updiscon: {}, privilege: {}",
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
            self.privilege
        ))
    }
}

#[derive(Debug, Copy, Clone)]
pub enum ReportReason {
    CopyStateAddr,
    NextPcLocalPrevAddr,
    NextPcPrevAddr,
    NextPcAddr,
}

pub struct Tracer<'a> {
    pub state: TraceState,
    proto_conf: ProtocolConfiguration,
    trace_conf: TraceConfiguration<'a>,
    report_pc: fn(ReportReason, u64),
    report_epc: fn(u64),
    report_trap: fn(Trap),
    report_instr: fn(Instruction),
    report_branch: fn(usize, u32, bool),
}

impl<'a> Tracer<'a> {
    pub fn new(
        proto_conf: ProtocolConfiguration,
        trace_conf: TraceConfiguration<'a>,
        report_pc: fn(ReportReason, u64),
        report_epc: fn(u64),
        report_trap: fn(Trap),
        report_instr: fn(Instruction),
        report_branch: fn(usize, u32, bool),
    ) -> Self {
        Tracer {
            state: TraceState {
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
                privilege: 0,
            },
            trace_conf,
            proto_conf,
            report_pc,
            report_epc,
            report_trap,
            report_instr,
            report_branch,
        }
    }

    fn get_instr(&mut self, pc: u64) -> Result<Instruction, TraceErrorType> {
        // TODO maybe optimize by saving index
        let segment = match self.trace_conf.segments.iter().find(|mem| mem.contains(pc)) {
            None => return Err(TraceErrorType::SegmentationFault(pc)),
            Some(segment) => segment,
        };
        let binary = match unsafe { BinaryInstruction::read_binary(pc, segment) } {
            Ok(binary) => binary,
            Err((value, num)) => {
                return Err(TraceErrorType::UnknownInstruction {
                    address: pc,
                    value,
                    truncated: num,
                    segment: *segment,
                })
            }
        };

        match binary {
            BinaryInstruction::Bit32(_) => assert_eq!(pc % 4, 0, "32 bit instruction not aligned"),
            BinaryInstruction::Bit16(_) => assert_eq!(pc % 2, 0, "16 bit instruction not aligned"),
        }
        let instr = Instruction::from_binary(&binary);
        (self.report_instr)(instr);
        Ok(instr)
    }

    fn incr_pc(&mut self, incr: i32) {
        self.state.pc = if incr.is_negative() {
            self.state.pc - incr.wrapping_abs() as u64
        } else {
            self.state.pc + incr as u64
        }
    }

    pub fn recover_status_fields(&mut self, payload: &Payload) {
        if let Some(addr) = payload.get_address_info() {
            // TODO why "- 1"?
            let msb = (addr.address & (1 << (self.proto_conf.iaddress_width_p - 1))) != 0;
            self.state.notify = addr.notify != msb;
            self.state.updiscon = addr.updiscon != addr.notify;
        }
    }

    pub fn process_te_inst(&mut self, payload: &Payload) -> Result<(), TraceError> {
        self.recover_status_fields(payload);
        self._process_te_inst(payload)
            .map_err(|error_type| TraceError {
                state: self.state,
                error_type,
            })
    }

    fn _process_te_inst(&mut self, payload: &Payload) -> Result<(), TraceErrorType> {
        if let Payload::Synchronization(sync) = payload {
            if let Synchronization::Support(sup) = sync {
                return self.process_support(sup);
            } else if let Synchronization::Context(_ctx) = sync {
                todo!("context processing not yet implemented");
            } else if let Synchronization::Trap(trap) = sync {
                (self.report_trap)(*trap);
                if !trap.interrupt {
                    let addr = self.exception_address(trap)?;
                    (self.report_epc)(addr);
                }
                if !trap.thaddr {
                    return Ok(());
                }
            }
            self.state.inferred_address = false;
            self.state.address = payload.get_address();
            if self.state.address == 0 {
                return Err(TraceErrorType::AddressIsZero);
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
                (self.report_pc)(ReportReason::CopyStateAddr, self.state.pc);
                self.state.last_pc = self.state.pc;
            }
            self.state.privilege = sync.get_privilege()?;
            self.state.start_of_trace = false;
            Ok(())
        } else {
            if self.state.start_of_trace {
                return Err(TraceErrorType::StartOfTrace);
            }
            if matches!(payload, Payload::Address(_)) || payload.get_branches().unwrap_or(0) != 0 {
                self.state.stop_at_last_branch = false;
                if self.trace_conf.full_address {
                    self.state.address = payload.get_address();
                } else {
                    let addr = payload.get_address() as i64;
                    if addr.is_negative() {
                        self.state.address -= addr.wrapping_abs() as u64;
                    } else {
                        self.state.address += addr as u64;
                    }
                }
            }
            if let Payload::Branch(branch) = payload {
                self.state.stop_at_last_branch = branch.branches == 0;
                self.state.branch_map |= (branch.branch_map) << self.state.branches;
                self.state.branches = if branch.branches == 0 {
                    self.state.branches + 31
                } else {
                    self.state.branches + branch.branches
                };
            }
            self.follow_execution_path(payload)
        }
    }

    fn process_support(&mut self, support: &Support) -> Result<(), TraceErrorType> {
        if support.qual_status != QualStatus::NoChange {
            self.state.start_of_trace = true;

            if support.qual_status == QualStatus::EndedNtr && self.state.inferred_address {
                let local_previous_address = self.state.pc;
                self.state.inferred_address = false;
                loop {
                    let local_stop_here = self.next_pc(local_previous_address)?;
                    (self.report_pc)(ReportReason::NextPcLocalPrevAddr, self.state.pc);
                    if local_stop_here {
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }

    fn branch_limit(&mut self) -> Result<usize, TraceErrorType> {
        Ok(self.get_instr(self.state.pc)?.is_branch as usize)
    }

    fn follow_execution_path(&mut self, payload: &Payload) -> Result<(), TraceErrorType> {
        let previous_address = self.state.pc;
        let mut local_stop_here;
        loop {
            if self.state.inferred_address {
                local_stop_here = self.next_pc(previous_address)?;
                (self.report_pc)(ReportReason::NextPcPrevAddr, previous_address);
                if local_stop_here {
                    self.state.inferred_address = false;
                }
            } else {
                local_stop_here = self.next_pc(self.state.address)?;
                (self.report_pc)(ReportReason::NextPcAddr, self.state.pc);
                if self.state.branches == 1
                    && self.get_instr(self.state.pc)?.is_branch
                    && self.state.stop_at_last_branch
                {
                    self.state.stop_at_last_branch = true;
                    return Ok(());
                }
                if local_stop_here {
                    if self.state.branches > self.branch_limit()? {
                        return Err(TraceErrorType::UnprocessedBranches(self.branch_limit()?));
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
                {
                    self.state.inferred_address = true;
                    return Ok(());
                }
                if matches!(payload, Payload::Synchronization(_))
                    && self.state.pc == self.state.address
                    && self.state.branches == self.branch_limit()?
                    && (payload.get_privilege()? == self.state.privilege
                        || self.get_instr(self.state.last_pc)?.is_return_from_trap())
                {
                    return Ok(());
                }
            }
        }
    }

    fn next_pc(&mut self, address: u64) -> Result<bool, TraceErrorType> {
        let local_instr = self.get_instr(self.state.pc)?;
        let local_this_pc = self.state.pc;
        let mut local_stop_here = false;

        if local_instr.is_inferable_jump() {
            let imm = local_instr
                .imm
                .ok_or(TraceErrorType::ImmediateIsNone(local_instr))?;
            self.incr_pc(imm);
            if imm == 0 {
                local_stop_here = true;
            }
        } else if local_instr.is_uninferable_discon() {
            if self.state.stop_at_last_branch {
                return Err(TraceErrorType::UnexpectedUninferableDiscon);
            }
            self.state.pc = address;
            local_stop_here = true;
        } else if self.is_taken_branch(&local_instr)? {
            let imm = local_instr
                .imm
                .ok_or(TraceErrorType::ImmediateIsNone(local_instr))?;
            self.incr_pc(imm);
            if imm == 0 {
                local_stop_here = true;
            }
        } else {
            self.incr_pc(local_instr.size as i32)
        }

        self.state.last_pc = local_this_pc;

        Ok(local_stop_here)
    }

    fn is_taken_branch(&mut self, instr: &Instruction) -> Result<bool, TraceErrorType> {
        if !instr.is_branch {
            return Ok(false);
        }
        if self.state.branches == 0 {
            return Err(TraceErrorType::UnresolvableBranch);
        }
        let local_taken = self.state.branch_map & 1 == 0;
        (self.report_branch)(self.state.branches, self.state.branch_map, local_taken);
        self.state.branches -= 1;
        self.state.branch_map >>= 1;
        Ok(local_taken)
    }

    fn exception_address(&mut self, trap: &Trap) -> Result<u64, TraceErrorType> {
        let local_instr = self.get_instr(self.state.pc)?;

        if local_instr.is_uninferable_discon() && trap.thaddr {
            Ok(trap.address)
        } else if local_instr.name == ecall
            || local_instr.name == ebreak
            || local_instr.name == c_ebreak
        {
            Ok(self.state.pc)
        } else {
            panic!("WHAT IS THIS HERE???") //Ok(self.next_pc(self.state.pc)?)
        }
    }
}
