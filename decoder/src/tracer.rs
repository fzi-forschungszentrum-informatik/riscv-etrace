use crate::decoder::payload::{Payload, QualStatus, Support, Synchronization, Trap};
use crate::disassembler::Name::{c_ebreak, ebreak, ecall};
use crate::disassembler::{BinaryInstruction, Instruction};
use crate::tracer::TraceError::UnresolvableBranch;
use crate::{ProtocolConfiguration, TraceConfiguration};

pub enum TraceError {
    AddressIsZero(TracerState),
    StartOfTrace(TracerState),
    UnprocessedBranches {
        state: TracerState,
        branch_limit: usize,
    },
    ImmediateIsNone {
        state: TracerState,
        instr: Instruction,
    },
    UnexpectedUninferableDiscon(TracerState),
    UnresolvableBranch(TracerState),
    WrongGetBranchType {
        state: TracerState,
        sync: Synchronization   
    },
    UnknownInstruction {
        state: TracerState,
        address: u64,
    }
}

#[derive(Copy, Clone)]
pub struct TracerState {
    pc: u64,
    last_pc: u64,
    branches: usize,
    branch_map: u32,
    stop_at_last_branch: bool,
    inferred_address: bool,
    start_of_trace: bool,
    address: u64,
    notify: bool,
    updiscon: bool,
}

pub struct Tracer {
    state: TracerState,
    proto_conf: ProtocolConfiguration,
    trace_conf: TraceConfiguration,
    report_pc: fn(u64),
    report_epc: fn(u64),
    report_trap: fn(&Trap),
}

impl Tracer {
    fn new(
        proto_conf: ProtocolConfiguration,
        trace_conf: TraceConfiguration,
        report_pc: fn(u64),
        report_epc: fn(u64),
        report_trap: fn(&Trap),
    ) -> Self {
        Tracer {
            state: TracerState {
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
            },
            trace_conf,
            proto_conf,
            report_pc,
            report_epc,
            report_trap,
        }
    }

    fn get_instr(&self, pc: u64) -> Result<Instruction, TraceError> {
        assert!(
            pc >= self.trace_conf.binary_start && pc < self.trace_conf.binary_end,
            "pc not in binary"
        );
        let binary = match unsafe { BinaryInstruction::read_binary(pc as *const u64) } {
            Ok(binary) => binary, 
            Err(()) => {
                return Err(TraceError::UnknownInstruction {
                    state: self.state,
                    address: pc,
                })
            }
        };
        
        match binary {
            BinaryInstruction::Bit32(_) => assert_eq!(pc % 4, 0, "32 bit instruction not aligned"),
            BinaryInstruction::Bit16(_) => assert_eq!(pc % 2, 0, "16 bit instruction not aligned"),
        }
        Ok(Instruction::from_binary(&binary))
    }

    fn incr_pc(&mut self, incr: u64) {
        self.state.pc += incr;
    }

    pub fn recover_status_fields(&mut self, payload: &Payload) {
        if let Some(addr) = payload.get_address() {
            // TODO why "- 1"?
            let msb = (addr.address & (1 << (self.proto_conf.iaddress_width_p - 1))) != 0;
            self.state.notify = addr.notify != msb;
            self.state.updiscon = addr.updiscon != addr.notify;
        }
    }

    pub fn process_te_inst(&mut self, payload: &Payload) -> Result<(), TraceError> {
        if let Payload::Synchronization(sync) = payload {
            if let Synchronization::Support(sup) = sync {
                self.process_support(sup)?
            } else if let Synchronization::Context(_ctx) = sync {
                todo!("context processing not yet implemented");
            } else if let Synchronization::Trap(trap) = sync {
                (self.report_trap)(trap);
                if !trap.interrupt {
                    let addr = self.exception_address(trap)?;
                    (self.report_epc)(addr);
                }
                if !trap.thaddr {
                    return Ok(());
                }
            }
            self.state.inferred_address = false;
            self.state.address = payload.get_address().unwrap().address;
            if self.state.address == 0 {
                return Err(TraceError::AddressIsZero(self.state));
            }
            if matches!(sync, Synchronization::Trap(_)) || self.state.start_of_trace {
                self.state.branches = 0;
                self.state.branch_map = 0;
            }
            if self.get_instr(self.state.address)?.is_branch {
                let branch = match sync.get_branch() {
                    Ok(branch) => branch as u32,
                    Err(()) => {
                        return Err(TraceError::WrongGetBranchType {
                            state: self.state,
                            sync: *sync,
                        })
                    }
                };
                self.state.branch_map |= branch << self.state.branches;
                self.state.branches += 1;
            }
            if matches!(payload, Payload::Synchronization(Synchronization::Start(_)))
                && !self.state.start_of_trace
            {
                self.follow_execution_path(self.state.address, payload)?
            } else {
                self.state.pc = self.state.address;
                (self.report_pc)(self.state.pc);
                self.state.last_pc = self.state.pc;
            }
            self.state.start_of_trace = false;
        } else {
            if self.state.start_of_trace {
                return Err(TraceError::StartOfTrace(self.state));
            }
            if matches!(payload, Payload::Address(_)) || payload.get_branches().unwrap_or(0) != 0 {
                self.state.stop_at_last_branch = false;
                if self.trace_conf.full_address {
                    self.state.address = payload.get_address().unwrap().address;
                } else {
                    self.state.address += payload.get_address().unwrap().address;
                }
            }
            if let Payload::Branch(branch) = payload {
                self.state.stop_at_last_branch = branch.branches == 0;
                self.state.branch_map |= branch.branch_map << self.state.branches;
                self.state.branches = if branch.branches == 0 {
                    self.state.branches + 31
                } else {
                    self.state.branches + branch.branches
                };
            }
        }
        Ok(())
    }

    fn process_support(&mut self, support: &Support) -> Result<(), TraceError> {
        if support.qual_status != QualStatus::NoChange {
            self.state.start_of_trace = true;

            if support.qual_status == QualStatus::EndedNtr && self.state.inferred_address {
                let local_previous_address = self.state.pc;
                self.state.inferred_address = false;
                loop {
                    let local_stop_here = self.next_pc(local_previous_address)?;
                    (self.report_pc)(self.state.pc);
                    if local_stop_here {
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }

    fn follow_execution_path(&mut self, address: u64, payload: &Payload) -> Result<(), TraceError> {
        fn branch_limit(tracer: &Tracer) -> Result<usize, TraceError> {
            if tracer.get_instr(tracer.state.pc)?.is_branch {
                Ok(1)
            } else {
                Ok(0)
            }
        }
        let previous_address = self.state.pc;
        let mut local_stop_here;
        loop {
            if self.state.inferred_address {
                local_stop_here = self.next_pc(previous_address)?;
                (self.report_pc)(previous_address);
                if local_stop_here {
                    self.state.inferred_address = false;
                }
            } else {
                local_stop_here = self.next_pc(address)?;
                (self.report_pc)(self.state.pc);
                if self.state.branches == 1
                    && self.get_instr(self.state.pc)?.is_branch
                    && self.state.stop_at_last_branch
                {
                    self.state.stop_at_last_branch = true;
                    return Ok(());
                }
                if local_stop_here {
                    if self.state.branches > branch_limit(self)? {
                        return Err(TraceError::UnprocessedBranches {
                            state: self.state,
                            branch_limit: branch_limit(self)?,
                        });
                    }
                    return Ok(());
                }
                if !matches!(payload, Payload::Synchronization(_))
                    && self.state.pc == address
                    && !self.state.stop_at_last_branch
                    && self.state.notify
                    && self.state.branches == branch_limit(self)?
                {
                    return Ok(());
                }
                if !matches!(payload, Payload::Synchronization(_))
                    && self.state.pc == address
                    && !self.state.stop_at_last_branch
                    && !&self.get_instr(self.state.last_pc)?.is_uninferable_discon()
                    && !self.state.updiscon
                    && self.state.branches == branch_limit(self)?
                {
                    self.state.inferred_address = true;
                    return Ok(());
                }
                if matches!(payload, Payload::Synchronization(_))
                    && self.state.pc == address
                    && self.state.branches == branch_limit(self)?
                {
                    return Ok(());
                }
            }
        }
    }

    fn next_pc(&mut self, address: u64) -> Result<bool, TraceError> {
        let local_instr = self.get_instr(self.state.pc)?;
        let local_this_pc = self.state.pc;
        let mut local_stop_here = false;

        if local_instr.is_inferable_jump() {
            match local_instr.imm {
                Some(imm) => {
                    self.incr_pc(imm as u64);
                    if imm == 0 {
                        local_stop_here = true;
                    }
                }
                None => {
                    return Err(TraceError::ImmediateIsNone {
                        state: self.state,
                        instr: local_instr,
                    });
                }
            }
        } else if local_instr.is_uninferable_discon() {
            if self.state.stop_at_last_branch {
                return Err(TraceError::UnexpectedUninferableDiscon(self.state));
            }
            self.state.pc = address;
            local_stop_here = true;
        } else if self.is_taken_branch(&local_instr)? {
            match local_instr.imm {
                Some(_) => {
                    self.incr_pc(local_instr.imm.unwrap() as u64);
                    if local_instr.imm.unwrap() == 0 {
                        local_stop_here = true;
                    }
                }
                None => {
                    return Err(TraceError::ImmediateIsNone {
                        state: self.state,
                        instr: local_instr,
                    });
                }
            }
        } else {
            self.incr_pc(local_instr.size as u64)
        }

        self.state.last_pc = local_this_pc;

        Ok(local_stop_here)
    }

    fn is_taken_branch(&mut self, instr: &Instruction) -> Result<bool, TraceError> {
        if !instr.is_branch {
            return Ok(false);
        }
        if self.state.branches == 0 {
            return Err(UnresolvableBranch(self.state));
        }
        let local_taken = self.state.branch_map & 1 == 0;
        self.state.branches -= 1;
        self.state.branch_map >>= 1;
        Ok(local_taken)
    }

    fn exception_address(&mut self, trap: &Trap) -> Result<u64, TraceError> {
        let local_instr = self.get_instr(self.state.pc)?;
        let local_address;

        if local_instr.is_uninferable_discon() && trap.thaddr {
            local_address = trap.address
        } else if local_instr.name == ecall
            || local_instr.name == ebreak
            || local_instr.name == c_ebreak
        {
            local_address = self.state.pc;
        } else {
            // TODO is the python code correct?
            local_address = self.next_pc(self.state.pc)? as u64;
        }
        Ok(local_address)
    }
}
