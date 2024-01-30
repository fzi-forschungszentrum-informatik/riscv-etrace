use crate::decoder::payload::{Payload, QualStatus, Support, Synchronization, Trap};
use crate::disassembler::OpCode::{
    c_ebreak, c_j, c_jal, c_jalr, c_jr, dret, ebreak, ecall, jal, jalr, mret, sret, uret,
};
use crate::disassembler::{BinaryInstruction, Instruction};
use crate::TraceConfiguration;

struct Tracer {
    pc: u64,
    last_pc: u64,
    branches: usize,
    branch_map: u32,
    stop_at_last_branch: bool,
    inferred_address: bool,
    start_of_trace: bool,
    address: u64,
    conf: TraceConfiguration,
    notify: bool,
    updiscon: bool,
}

impl Tracer {
    fn get_instr(&self, pc: u64) -> Instruction {
        let binary = unsafe { BinaryInstruction::read_binary(pc) };
        Instruction::from_binary(&binary)
    }

    fn incr_pc(&mut self, incr: u64) {
        self.pc += incr;
    }

    fn recover_status_fields(&mut self, payload: &Payload) {
        if let Some(addr) = payload.get_address() {
            // TODO why "- 1"?
            let msb = (addr.address & (1 << (self.conf.iaddress_width_p - 1))) != 0;
            self.notify = addr.notify != msb;
            self.updiscon = addr.updiscon != addr.notify;
        }
    }

    fn process_te_inst(&mut self, payload: &Payload) {
        if let Payload::Synchronization(sync) = payload {
            if let Synchronization::Support(sup) = sync {
                self.process_support(sup)
            } else if let Synchronization::Context(_ctx) = sync {
                todo!("context processing not yet implemented");
            } else if let Synchronization::Trap(trap) = sync {
                self.report_trap(trap);
                if !trap.interrupt {
                    let addr = self.exception_address(trap);
                    self.report_epc(addr);
                }
                if !trap.thaddr {
                    return;
                }
            }
            self.inferred_address = false;
            self.address = payload.get_address().unwrap().address;
            assert_ne!(self.address, 0);
            if matches!(sync, Synchronization::Trap(_)) || self.start_of_trace {
                self.branches = 0;
                self.branch_map = 0;
            }
            if self.get_instr(self.address).is_branch() {
                self.branch_map |= (sync.get_branch() as u32) << self.branches;
                self.branches += 1;
            }
            if matches!(payload, Payload::Synchronization(Synchronization::Start(_)))
                && !self.start_of_trace
            {
                self.follow_execution_path(self.address, payload)
            } else {
                self.pc = self.address;
                self.report_pc(self.pc);
                self.last_pc = self.pc;
            }
            self.start_of_trace = false;
        } else {
            assert!(!self.start_of_trace);
            if matches!(payload, Payload::Address(_)) || payload.get_branches().unwrap_or(0) != 0 {
                self.stop_at_last_branch = false;
                if self.conf.full_address {
                    self.address = payload.get_address().unwrap().address;
                } else {
                    self.address += payload.get_address().unwrap().address;
                }
            }
            if let Payload::Branch(branch) = payload {
                self.stop_at_last_branch = branch.branches == 0;
                self.branch_map |= branch.branch_map << self.branches;
                self.branches = if branch.branches == 0 {
                    self.branches + 31
                } else {
                    self.branches + branch.branches
                };
            }
        }
    }

    fn process_support(&mut self, support: &Support) {
        if support.qual_status != QualStatus::NoChange {
            self.start_of_trace = true;

            if support.qual_status == QualStatus::EndedNtr && self.inferred_address {
                let local_previous_address = self.pc;
                self.inferred_address = false;
                loop {
                    let local_stop_here = self.next_pc(local_previous_address);
                    self.report_pc(self.pc);
                    if local_stop_here {
                        return;
                    }
                }
            }
        }
    }

    fn follow_execution_path(&mut self, address: u64, payload: &Payload) {
        fn branch_limit(tracer: &Tracer) -> usize {
            if tracer.get_instr(tracer.pc).is_branch() {
                1
            } else {
                0
            }
        }
        let previous_address = self.pc;
        let mut local_stop_here = false;
        loop {
            if self.inferred_address {
                local_stop_here = self.next_pc(previous_address);
                self.report_pc(previous_address);
                if local_stop_here {
                    self.inferred_address = false;
                }
            } else {
                local_stop_here = self.next_pc(address);
                self.report_pc(self.pc);
                if self.branches == 1
                    && self.get_instr(self.pc).is_branch()
                    && self.stop_at_last_branch
                {
                    self.stop_at_last_branch = true;
                    return;
                }
                if local_stop_here {
                    assert!(
                        self.branches <= branch_limit(self),
                        "Error: unprocessed branches"
                    );
                    return;
                }
                if !matches!(payload, Payload::Synchronization(_))
                    && self.pc == address
                    && !self.stop_at_last_branch
                    && self.notify
                    && self.branches == branch_limit(self)
                {
                    return;
                }
                if !matches!(payload, Payload::Synchronization(_))
                    && self.pc == address
                    && !self.stop_at_last_branch
                    && !self.is_uninferable_discon(&self.get_instr(self.last_pc))
                    && !self.updiscon
                    && self.branches == branch_limit(self)
                // && ignore return stack
                {
                    self.inferred_address = true;
                    return;
                }
                if matches!(payload, Payload::Synchronization(_))
                    && self.pc == address
                    && self.branches == branch_limit(self)
                {
                    return;
                }
            }
        }
    }

    fn next_pc(&mut self, address: u64) -> bool {
        let local_instr = self.get_instr(self.pc);
        let local_this_pc = self.pc;
        let mut local_stop_here = false;

        if self.is_inferable_jump(&local_instr) {
            assert!(local_instr.imm.is_some());
            self.incr_pc(local_instr.imm.unwrap() as u64);
            if local_instr.imm.unwrap()  == 0 {
                local_stop_here = true;
            }
        } else if self.is_uninferable_discon(&local_instr) {
            assert!(
                !self.stop_at_last_branch,
                "Error: Unexpected uninferable discontinuity"
            );
            self.pc = address;
            local_stop_here = true;
        } else if self.is_taken_branch(&local_instr) {
            assert!(local_instr.imm.is_some());
            self.incr_pc(local_instr.imm.unwrap() as u64);
            if local_instr.imm.unwrap() == 0 {
                local_stop_here = true;
            }
        } else {
            self.incr_pc(local_instr.size as u64)
        }

        self.last_pc = local_this_pc;

        local_stop_here
    }

    fn is_taken_branch(&mut self, instr: &Instruction) -> bool {
        if !instr.is_branch() {
            return false;
        }
        assert_ne!(self.branches, 0, "Error: cannot resolve branch");
        let local_taken = self.branch_map & 1 == 0;
        self.branches -= 1;
        self.branch_map >>= 1;
        local_taken
    }

    fn is_inferable_jump(&self, instr: &Instruction) -> bool {
        instr.opcode == jal
            || instr.opcode == c_jal
            || instr.opcode == c_j
            || (instr.opcode == jalr && instr.is_rs1_zero)
    }

    fn is_uninferable_jump(&self, instr: &Instruction) -> bool {
        instr.opcode == c_jalr
            || instr.opcode == c_jr
            || (instr.opcode == jalr && !instr.is_rs1_zero)
    }

    fn is_uninferable_discon(&self, instr: &Instruction) -> bool {
        self.is_uninferable_jump(instr)
            || instr.opcode == uret
            || instr.opcode == sret
            || instr.opcode == mret
            || instr.opcode == dret
            || instr.opcode == ecall
            || instr.opcode == ebreak
            || instr.opcode == c_ebreak
    }

    fn exception_address(&mut self, trap: &Trap) -> u64 {
        let local_instr = self.get_instr(self.pc);
        let local_address;

        if self.is_uninferable_discon(&local_instr) && trap.thaddr {
            local_address = trap.address
        } else if local_instr.opcode == ecall
            || local_instr.opcode == ebreak
            || local_instr.opcode == c_ebreak
        {
            local_address = self.pc;
        } else {
            // TODO is the python code correct?
            local_address = self.next_pc(self.pc) as u64;
        }
        local_address
    }

    fn report_pc(&self, address: u64) {
        todo!()
    }

    fn report_epc(&self, address: u64) {
        todo!()
    }

    fn report_trap(&self, trap: &Trap) {
        todo!()
    }
}
