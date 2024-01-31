use crate::disassembler::InstructionType::{Ignored, B, CB, CJ, I, J};
use crate::disassembler::OpCode::{c_benz, c_beqz, c_ebreak, c_j, c_jalr, c_jr};

#[derive(Copy, Clone)]
pub enum BinaryInstruction {
    Bit32(u32),
    Bit16(u16),
}

impl BinaryInstruction {
    pub unsafe fn read_binary(address: u64) -> Self {
        const MASK_32_BITS: u64 = 0xFFFFFFFF;
        let bits = u32::try_from(MASK_32_BITS & *(address as *const u64)).unwrap();
        let bytes = bits.to_be_bytes();
        if bytes[0] & 0x3 == 0x3 {
            return BinaryInstruction::Bit16(u16::from_be_bytes(bytes[0..2].try_into().unwrap()));
        } else if bytes[0] & 0x1F < 0x1F {
            return BinaryInstruction::Bit32(bits);
        }
        panic!("Cannot parse instruction at {:?}", address);
    }

    pub fn value(self) -> u32 {
        match self {
            BinaryInstruction::Bit32(num) => num,
            BinaryInstruction::Bit16(num) => num as u32,
        }
    }

    pub fn size(&self) -> u32 {
        match self {
            BinaryInstruction::Bit32(_) => 8,
            BinaryInstruction::Bit16(_) => 4,
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Eq, PartialEq)]
pub enum OpCode {
    // SYS (I)
    ecall,
    ebreak,
    mret,
    sret,
    uret,
    dret,
    fence,
    fence_i,
    sfence_vma,
    wfi,
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

impl OpCode {
    fn read_instr(bin_instr: &BinaryInstruction) -> Self {
        const MASK_32_BIT_OPCODE: u32 = 0x7F;
        const MASK_16_BIT_OPCODE: u16 = 0x3;
        match bin_instr {
            BinaryInstruction::Bit32(num) => Self::parse_full_instr(*num),
            BinaryInstruction::Bit16(num) => Self::parse_compressed_instr(*num),
        }
    }

    fn parse_full_instr(num: u32) -> Self {
        const OPCODE_MASK: u32 = 0x7F;
        let opcode = num & OPCODE_MASK;
        match opcode {
            0b1100011 => Self::parse_b_type(num),
            0b1101111 => Self::parse_j_type(num),
            0b1100111 => Self::parse_i_type(num),
            _ => OpCode::Ignored,
        }
    }

    fn parse_b_type(num: u32) -> Self {
        todo!()
    }

    fn parse_j_type(num: u32) -> Self {
        todo!()
    }

    fn parse_i_type(num: u32) -> Self {
        todo!()
    }

    fn parse_compressed_instr(num: u16) -> Self {
        const MASK_OP: u16 = 0x3;
        const MASK_FUNCT3: u16 = 0xE000;
        let op = num & MASK_OP;
        let funct3 = (num & MASK_FUNCT3) >> 13;
        match op {
            0b01 => match funct3 {
                0b101 => c_j,
                0b110 => c_beqz,
                0b111 => c_benz,
                _ => OpCode::Ignored,
            },
            0b10 => {
                const MASK_BIT_12: u16 = 0x800;
                const MASK_RS1: u16 = 0xF80;
                const MASK_RS2: u16 = 0x7C;
                let bit12 = (num & MASK_BIT_12) >> 12;
                let rs1 = (num & MASK_RS1) >> 7;
                let rs2 = (num & MASK_RS2) >> 2;
                if funct3 != 0b100 {
                    return OpCode::Ignored;
                }
                if bit12 == 0 && rs1 != 0 && rs2 == 0 {
                    return c_jr;
                }
                if bit12 == 1 && rs1 == 0 && rs2 == 0 {
                    return c_ebreak;
                }
                if bit12 == 1 && rs1 != 0 && rs2 == 0 {
                    return c_jalr;
                }
                OpCode::Ignored
            }
            _ => OpCode::Ignored,
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Eq, PartialEq)]
pub enum InstructionType {
    B,
    CB,
    J,
    CJ,
    I,
    Ignored,
}

// only used for is_infer_jump
// 1) jal (J) c.jal (CJ) c.j (CJ) jalr (I)
// 2) b or cb type
impl InstructionType {
    pub fn from_opcode(op_code: &OpCode) -> Self {
        match op_code {
            OpCode::jal => J,
            OpCode::c_jal => CJ,
            OpCode::c_j => CJ,
            OpCode::jalr => I,
            OpCode::beq => B,
            OpCode::bne => B,
            OpCode::blt => B,
            OpCode::bge => B,
            OpCode::bltu => B,
            OpCode::bgeu => B,
            OpCode::c_beqz => CB,
            OpCode::c_benz => CB,
            _ => Ignored,
        }
    }

    fn calc_imm(&self, num: u32) -> Option<u32> {
        match self {
            CB => Self::calc_imm_cb(num as u16),
            CJ => Self::calc_imm_cj(num as u16),
            B => Self::calc_imm_b(num),
            J => Self::calc_imm_j(num),
            I => Self::calc_imm_i(num),
            Ignored => None,
        }
    }

    fn calc_imm_cb(num: u16) -> Option<u32> {
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
        Some(imm as u32)
    }

    fn calc_imm_cj(num: u16) -> Option<u32> {
        const MASK: u16 = 0b0001_1111_1111_1100;
        Some(((num & MASK) >> 2) as u32)
    }

    fn calc_imm_b(num: u32) -> Option<u32> {
        const MASK_IMM_BIT_1_TO_4: u32 = 0xF00;
        const MASK_IMM_BIT_5_TO_10: u32 = 0x1E000000;
        const MASK_IMM_BIT_11: u32 = 0x40;
        const MASK_IMM_BIT_12: u32 = 1 << 31;
        let mut imm = 0u32;
        imm |= (num & MASK_IMM_BIT_1_TO_4) >> 4;
        imm |= (num & MASK_IMM_BIT_5_TO_10) >> 15;
        imm |= (num & MASK_IMM_BIT_11) << 4;
        imm |= (num & MASK_IMM_BIT_12) >> 20;
        Some(imm)
    }

    fn calc_imm_j(num: u32) -> Option<u32> {
        const MASK_IMM_BIT_1_TO_10: u32 = 0x7FC00000;
        const MASK_IMM_BIT_11: u32 = 0x10000;
        const MASK_IMM_BIT_12_TO_19: u32 = 0x7F000;
        const MASK_IMM_BIT_20: u32 = 1 << 31;
        let mut imm = 0u32;
        imm |= (num & MASK_IMM_BIT_1_TO_10) >> 16;
        imm |= (num & MASK_IMM_BIT_11) >> 9;
        imm |= num & MASK_IMM_BIT_12_TO_19;
        imm |= (num & MASK_IMM_BIT_20) >> 12;
        Some(imm)
    }

    fn calc_imm_i(num: u32) -> Option<u32> {
        const MASK: u32 = 0xFFF00000;
        Some((num & MASK) >> 20)
    }
}

pub struct Instruction {
    pub opcode: OpCode,
    pub instr_type: InstructionType,
    pub imm: Option<u32>,
    pub is_rs1_zero: bool,
    pub size: u32,
}

impl Instruction {
    pub fn from_binary(bin_instr: &BinaryInstruction) -> Self {
        let opcode = OpCode::read_instr(bin_instr);
        let instr_type = InstructionType::from_opcode(&opcode);
        let size = bin_instr.size();
        let imm = instr_type.calc_imm(bin_instr.value());
        let is_rs1_zero = true;
        Instruction {
            opcode,
            instr_type,
            size,
            imm,
            is_rs1_zero,
        }
    }

    pub fn is_branch(&self) -> bool {
        self.instr_type == B || self.instr_type == CB
    }
}

/*struct KnownInstruction {
    pattern: u32,
    mask: u32,
    instruction_type: InstructionType,
}

#[rustfmt::skip]
static KNOWN_INSTR: [KnownInstruction; 11] = [
    KnownInstruction { pattern: 0x00000073, mask: 0xffefffff, instruction_type: Ecall  }, // ecall, ebreak
    KnownInstruction { pattern: 0x00200073, mask: 0xefffffff, instruction_type: Unfer  }, // uret, sret
    KnownInstruction { pattern: 0x30200073, mask: 0xffffffff, instruction_type: Unfer  }, // mret
    KnownInstruction { pattern: 0x12000073, mask: 0xfe007fff, instruction_type: Normal }, // sfence.vma
    KnownInstruction { pattern: 0x10400073, mask: 0xfff07fff, instruction_type: Normal }, // sfence.vm
    KnownInstruction { pattern: 0x0000006f, mask: 0x0000007f, instruction_type: Infer  }, // jal
    KnownInstruction { pattern: 0x0000006f, mask: 0x0000707f, instruction_type: Infer  }, // jalr
    KnownInstruction { pattern: 0x00000063, mask: 0x0000607f, instruction_type: Branch }, // beq, bne
    KnownInstruction { pattern: 0x00004063, mask: 0x0000607f, instruction_type: Branch }, // blt, bge
    KnownInstruction { pattern: 0x00006063, mask: 0x0000607f, instruction_type: Branch }, // bltu, bgeu
    KnownInstruction { pattern: 0x0000000f, mask: 0x0000607f, instruction_type: Normal }, // fence, fence.i
];

#[rustfmt::skip]
static KNOWN_COMPRESSED_INSTR: [KnownInstruction; 4] = [
    KnownInstruction { pattern: 0x9002, mask: 0xffff, instruction_type: Ecall  }, // c.ebreak
    KnownInstruction { pattern: 0xa001, mask: 0xe003, instruction_type: Infer  }, // c.j
    KnownInstruction { pattern: 0xc001, mask: 0xc003, instruction_type: Branch }, // c.beqz, c.bnez
    KnownInstruction { pattern: 0x8002, mask: 0xe07f, instruction_type: Unfer  }, // c.jr, c.jalr
];*/
