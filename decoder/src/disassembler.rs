use crate::disassembler::Name::*;
use crate::disassembler::OpCode::*;

#[derive(Copy, Clone)]
pub enum BinaryInstruction {
    Bit32(u32),
    Bit16(u16),
}

impl BinaryInstruction {
    pub unsafe fn read_binary(address: *const u64) -> Result<Self, ()> {
        const MASK_32_BITS: u64 = 0xFFFFFFFF;
        let le_bytes = u32::try_from(MASK_32_BITS & *address).unwrap();
        let be_bytes = le_bytes.to_be_bytes();
        if (be_bytes[0] & 0x3) == 0x3 {
            Ok(BinaryInstruction::Bit16(u16::from_be_bytes(
                be_bytes[0..2].try_into().unwrap(),
            )))
        } else if (be_bytes[0] & 0x1F) >= 0x3 && (be_bytes[0] & 0x1F) < 0x1F {
            Ok(BinaryInstruction::Bit32(le_bytes))
        } else {
            Err(())
        }
    }
}

#[repr(u32)]
#[derive(Eq, PartialEq)]
enum OpCode {
    MiscMem = 0b0001111,
    Branch = 0b1100011,
    JALR = 0b1100111,
    JAL = 0b1101111,
    System = 0b1110011,
    Ignored,
}

impl From<u32> for OpCode {
    fn from(value: u32) -> Self {
        const MASK: u32 = 0x7F;
        match value & MASK {
            x if x == MiscMem as u32 => MiscMem,
            x if x == Branch as u32 => Branch,
            x if x == JALR as u32 => JALR,
            x if x == JAL as u32 => JAL,
            x if x == System as u32 => System,
            _ => OpCode::Ignored,
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Eq, PartialEq, Copy, Clone)]
pub enum Name {
    // SYS (R)
    mret,
    sret,
    uret, // ??? where how what why
    dret, // ???
    fence,
    sfence_vma,
    wfi,
    // I
    ecall,
    ebreak,
    // Zifencei
    fence_i,
    // B
    beq,
    bne,
    blt,
    bge,
    bltu,
    bgeu,
    // CB
    c_beqz,
    c_benz,
    // J
    jal,
    // CJ
    c_j,
    c_jal,
    // CR
    c_jr,
    c_jalr,
    c_ebreak,
    // I
    jalr,
    // other
    Ignored,
}

impl Name {
    fn calc_imm_cb(num: u16) -> u32 {
        const MASK_IMM_BIT_1_TO_2: u16 = 0x18;
        const MASK_IMM_BIT_3_TO_4: u16 = 0x1800;
        const MASK_IMM_BIT_5: u16 = 0x4;
        const MASK_IMM_BIT_6_TO_7: u16 = 0x60;
        const MASK_IMM_BIT_8: u16 = 0x1000;
        let mut imm = 0u16;
        imm |= (num & MASK_IMM_BIT_1_TO_2) >> 3;
        imm |= (num & MASK_IMM_BIT_3_TO_4) >> (10 - 2);
        imm |= (num & MASK_IMM_BIT_5) << 3;
        imm |= (num & MASK_IMM_BIT_6_TO_7) << 1;
        imm |= (num & MASK_IMM_BIT_8) >> (12 - 8);
        imm as u32
    }

    fn calc_imm_cj(num: u16) -> u32 {
        const MASK: u16 = 0b0001_1111_1111_1100;
        ((num & MASK) >> 2) as u32
    }

    fn calc_imm_b(num: u32) -> u32 {
        const MASK_IMM_BIT_1_TO_4: u32 = 0xF00;
        const MASK_IMM_BIT_5_TO_10: u32 = 0x1E000000;
        const MASK_IMM_BIT_11: u32 = 0x40;
        const MASK_IMM_BIT_12: u32 = 1 << 31;
        let mut imm = 0u32;
        imm |= (num & MASK_IMM_BIT_1_TO_4) >> 4;
        imm |= (num & MASK_IMM_BIT_5_TO_10) >> 15;
        imm |= (num & MASK_IMM_BIT_11) << 4;
        imm |= (num & MASK_IMM_BIT_12) >> 20;
        imm
    }

    fn calc_imm_j(num: u32) -> u32 {
        const MASK_IMM_BIT_1_TO_10: u32 = 0x7FC00000;
        const MASK_IMM_BIT_11: u32 = 0x10000;
        const MASK_IMM_BIT_12_TO_19: u32 = 0x7F000;
        const MASK_IMM_BIT_20: u32 = 1 << 31;
        let mut imm = 0u32;
        imm |= (num & MASK_IMM_BIT_1_TO_10) >> 16;
        imm |= (num & MASK_IMM_BIT_11) >> 9;
        imm |= num & MASK_IMM_BIT_12_TO_19;
        imm |= (num & MASK_IMM_BIT_20) >> 12;
        imm
    }

    fn calc_imm_i(num: u32) -> u32 {
        const MASK: u32 = 0xFFF00000;
        (num & MASK) >> 20
    }
}

pub struct Instruction {
    pub name: Name,
    pub is_rs1_zero: bool,
    pub size: u32,
    pub is_branch: bool,
    pub imm: Option<u32>,
}

impl Instruction {
    pub fn from_binary(bin_instr: &BinaryInstruction) -> Self {
        match bin_instr {
            BinaryInstruction::Bit32(num) => Self::parse_bin_instr(*num),
            BinaryInstruction::Bit16(num) => Self::parse_compressed_instr(*num),
        }
    }

    fn parse_bin_instr(num: u32) -> Self {
        let name;
        let mut is_rs1_zero = false;

        let opcode = OpCode::from(num);
        const MASK_RD: u32 = 0xF80;
        const MASK_FUNCT3: u32 = 0x7000;
        const MASK_RS1: u32 = 0xF8000;
        const MASK_RS2: u32 = 0x1F00000;
        const MASK_FUNCT7: u32 = 0xFE000000;

        let funct3 = (num & MASK_FUNCT3) >> 13;

        name = match opcode {
            MiscMem => match funct3 {
                0b000 => fence,
                0b010 => fence_i,
                _ => Name::Ignored,
            },
            Branch => match funct3 {
                0b000 => beq,
                0b001 => bne,
                0b100 => blt,
                0b101 => bge,
                0b110 => bltu,
                0b111 => bgeu,
                _ => Name::Ignored,
            },
            JALR => {
                is_rs1_zero = 0 == (num & MASK_RS1) >> 15;
                jalr
            }
            JAL => jal,
            System => {
                let funct3 = (num & MASK_FUNCT3) >> 13;
                let rd = (num & MASK_RD) >> 7;
                if rd != 0 || funct3 != 0 {
                    Name::Ignored
                } else {
                    let rs1 = (num & MASK_RS1) >> 15;
                    let funct7 = (num & MASK_FUNCT7) >> 25;
                    if rs1 == 0 {
                        let rs2 = (num & MASK_RS2) >> 20;
                        if rs2 == 0 && funct7 == 0 {
                            ecall
                        } else if rs2 == 1 && funct7 == 0 {
                            ebreak
                        } else if rs2 == 0b00010 && funct7 == 0b0001000 {
                            mret
                        } else if rs2 == 0b00010 && funct7 == 0b0001000 {
                            sret
                        } else if rs2 == 0b00101 && funct7 == 0b0001000 {
                            wfi
                        } else {
                            Name::Ignored
                        }
                    } else {
                        if funct7 == 0b0001001 {
                            sfence_vma
                        } else {
                            Name::Ignored
                        }
                    }
                }
            }
            OpCode::Ignored => Name::Ignored,
        };
        Instruction {
            name,
            is_rs1_zero,
            size: 4,
            is_branch: opcode == Branch,
            imm: Self::calc_imm(name, is_rs1_zero, opcode == Branch, num),
        }
    }

    fn calc_imm(name: Name, is_rs1_zero: bool, is_branch: bool, num: u32) -> Option<u32> {
        if is_branch {
            Some(Name::calc_imm_b(num))
        } else {
            match name {
                jal => Some(Name::calc_imm_j(num)),
                jalr if is_rs1_zero => Some(Name::calc_imm_i(num)),
                _ => None,
            }
        }
    }

    fn parse_compressed_instr(num: u16) -> Self {
        const MASK_OP: u16 = 0x3;
        const MASK_FUNCT3: u16 = 0xE000;
        const MASK_BIT_12: u16 = 0x800;
        const MASK_RS1: u16 = 0xF80;
        const MASK_RS2: u16 = 0x7C;

        let op = num & MASK_OP;
        let funct3 = (num & MASK_FUNCT3) >> 13;

        let name = match op {
            0b01 => match funct3 {
                0b101 => c_j,
                0b110 => c_beqz,
                0b111 => c_benz,
                _ => Name::Ignored,
            },
            0b10 => {
                let bit12 = (num & MASK_BIT_12) >> 12;
                let rs1 = (num & MASK_RS1) >> 7;
                let rs2 = (num & MASK_RS2) >> 2;
                if funct3 != 0b100 {
                    Name::Ignored
                } else {
                    if bit12 == 0 && rs1 != 0 && rs2 == 0 {
                        c_jr
                    } else if bit12 == 1 && rs1 == 0 && rs2 == 0 {
                        c_ebreak
                    } else if bit12 == 1 && rs1 != 0 && rs2 == 0 {
                        c_jalr
                    } else {
                        Name::Ignored
                    }
                }
            }
            _ => Name::Ignored,
        };
        let is_branch = op == 0b01;
        Instruction {
            is_branch,
            size: 2,
            is_rs1_zero: false,
            name,
            imm: Self::calc_compressed_imm(name, is_branch, num),
        }
    }

    fn calc_compressed_imm(name: Name, is_branch: bool, num: u16) -> Option<u32> {
        if is_branch {          
            Some(Name::calc_imm_cb(num))
        } else {
            match name {
                c_j => Some(Name::calc_imm_cj(num)),
                c_jal => Some(Name::calc_imm_cj(num)),
                _ => None
            }
        }
    }

    pub fn is_inferable_jump(&self) -> bool {
        matches!(self.name, jal)
            || matches!(self.name, c_jal)
            || matches!(self.name, c_j)
            || (matches!(self.name, jalr) && self.is_rs1_zero)
    }

    pub fn is_uninferable_jump(&self) -> bool {
        self.name == c_jalr || self.name == c_jr || (matches!(self.name, jalr) && !self.is_rs1_zero)
    }

    pub fn is_uninferable_discon(&self) -> bool {
        Self::is_uninferable_jump(self)
            || self.name == uret
            || self.name == sret
            || self.name == mret
            || self.name == dret
            || self.name == ecall
            || self.name == ebreak
            || self.name == c_ebreak
    }
}
