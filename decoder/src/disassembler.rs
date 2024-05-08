use crate::disassembler::Name::*;
use crate::disassembler::OpCode::*;
use core::ops::Range;

#[derive(Copy, Clone)]
pub enum BinaryInstruction {
    Bit32(u32),
    Bit16(u16),
}

impl BinaryInstruction {
    pub unsafe fn read_binary(address: u64, offset: i64) -> Result<Self, (u64, u32)> {
        const MASK_32_BITS: u64 = 0xFFFFFFFF;
        let pointer = (address as i64 + offset) as *const u64;

        let value = *pointer;
        let num = u32::try_from(MASK_32_BITS & value).unwrap();
        let bytes = num.to_le_bytes();
        if (bytes[0] & 0x3) != 0x3 {
            Ok(BinaryInstruction::Bit16(u16::from_be_bytes(
                bytes[0..2].try_into().unwrap(),
            )))
        } else if (bytes[0] & 0x1F) >= 0x3 && (bytes[0] & 0x1F) < 0x1F {
            Ok(BinaryInstruction::Bit32(num))
        } else {
            Err((value, num))
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
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Name {
    // SYS (R)
    mret,
    sret,
    uret, // TODO uret is legacy
    dret, // TODO dret is only in release candidate
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
    c_bnez,
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

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Instruction {
    pub name: Name,
    pub is_rs1_zero: bool,
    pub size: u32,
    pub is_branch: bool,
    pub imm: Option<u32>,
}

impl Instruction {
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

    pub fn from_binary(bin_instr: &BinaryInstruction) -> Self {
        match bin_instr {
            BinaryInstruction::Bit32(num) => Self::parse_bin_instr(*num),
            BinaryInstruction::Bit16(num) => Self::parse_compressed_instr(*num),
        }
    }

    fn rd(num: u32) -> u32 {
        Self::get_bits_u32(num, 7..12, 0)
    }

    fn funct3(num: u32) -> u32 {
        Self::get_bits_u32(num, 12..15, 0)
    }

    fn rs1(num: u32) -> u32 {
        Self::get_bits_u32(num, 15..20, 0)
    }

    fn rs2(num: u32) -> u32 {
        Self::get_bits_u32(num, 20..25, 0)
    }

    fn funct7(num: u32) -> u32 {
        Self::get_bits_u32(num, 25..32, 0)
    }

    fn parse_bin_instr(num: u32) -> Self {
        let name;
        let mut is_rs1_zero = false;

        let opcode = OpCode::from(num);

        let funct3 = Self::funct3(num);

        name = match opcode {
            MiscMem => match funct3 {
                0b000 => fence,
                0b001 => fence_i,
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
                is_rs1_zero = 0 == Self::rs1(num);
                jalr
            }
            JAL => jal,
            System => {
                let rd = Self::rd(num);
                if rd != 0 || funct3 != 0 {
                    Name::Ignored
                } else {
                    let rs1 = Self::rs1(num);
                    let funct7 = Self::funct7(num);
                    let rs2 = Self::rs2(num);
                    if rs2 == 0 && funct7 == 0 && rs1 == 0 {
                        ecall
                    } else if rs2 == 1 && funct7 == 0 && rs1 == 0 {
                        ebreak
                    } else if rs2 == 0b00010 && funct7 == 0b0001000 && rs1 == 0 {
                        sret
                    } else if rs2 == 0b00010 && funct7 == 0b0011000 && rs1 == 0 {
                        mret
                    } else if rs2 == 0b00101 && funct7 == 0b0001000 && rs1 == 0 {
                        wfi
                    } else if funct7 == 0b0001001 {
                        sfence_vma
                    } else {
                        Name::Ignored
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

    fn c_op(num: u16) -> u16 {
        Self::get_bits_u16(num, 0..2, 0)
    }

    fn c_funct3(num: u16) -> u16 {
        Self::get_bits_u16(num, 13..16, 0)
    }

    fn bit12(num: u16) -> bool {
        Self::get_bits_u16(num, 12..13, 0) == 1
    }

    fn c_rs1(num: u16) -> u16 {
        Self::get_bits_u16(num, 7..12, 0)
    }

    fn c_rs2(num: u16) -> u16 {
        Self::get_bits_u16(num, 2..7, 0)
    }

    fn parse_compressed_instr(num: u16) -> Self {
        let op = Self::c_op(num);
        let funct3 = Self::c_funct3(num);

        let name = match op {
            0b01 => match funct3 {
                0b001 => c_jal,
                0b101 => c_j,
                0b110 => c_beqz,
                0b111 => c_bnez,
                _ => Name::Ignored,
            },
            0b10 => {
                let bit12 = Self::bit12(num);
                let rs1 = Self::c_rs1(num);
                let rs2 = Self::c_rs2(num);
                if funct3 != 0b100 {
                    Name::Ignored
                } else {
                    if !bit12 && rs1 != 0 && rs2 == 0 {
                        c_jr
                    } else if bit12 && rs1 == 0 && rs2 == 0 {
                        c_ebreak
                    } else if bit12 && rs1 != 0 && rs2 == 0 {
                        c_jalr
                    } else {
                        Name::Ignored
                    }
                }
            }
            _ => Name::Ignored,
        };
        let is_branch = name == c_beqz || name == c_bnez;
        Instruction {
            is_branch,
            size: 2,
            is_rs1_zero: false,
            name,
            imm: Self::calc_compressed_imm(name, is_branch, num),
        }
    }

    fn calc_imm(name: Name, is_rs1_zero: bool, is_branch: bool, num: u32) -> Option<u32> {
        if is_branch {
            Some(Self::calc_imm_b(num))
        } else {
            match name {
                jal => Some(Self::calc_imm_j(num)),
                jalr if is_rs1_zero => Some(Self::calc_imm_i(num)),
                _ => None,
            }
        }
    }

    fn calc_compressed_imm(name: Name, is_branch: bool, num: u16) -> Option<u32> {
        if is_branch {
            Some(Self::calc_imm_cb(num))
        } else {
            match name {
                c_j => Some(Self::calc_imm_cj(num)),
                c_jal => Some(Self::calc_imm_cj(num)),
                _ => None,
            }
        }
    }

    fn mask_u32(r: &Range<i32>) -> u32 {
        ((1u32 << r.len()) - 1) << r.start
    }

    fn mask_u16(r: &Range<i32>) -> u16 {
        ((1u16 << r.len()) - 1) << r.start
    }

    // TODO should be a trait?
    fn get_bits_u32(source: u32, r: Range<i32>, start: i32) -> u32 {
        let mask = Self::mask_u32(&r);
        if r.start >= start {
            (source & mask) >> (r.start - start)
        } else {
            (source & mask) << (start - r.start)
        }
    }

    fn get_bits_u16(source: u16, r: Range<i32>, start: i32) -> u16 {
        let mask = Self::mask_u16(&r);
        if r.start >= start {
            (source & mask) >> (r.start - start)
        } else {
            (source & mask) << (start - r.start)
        }
    }

    fn calc_imm_cb(num: u16) -> u32 {
        const MASK_SIGN: u16 = 0xFF80;
        let mut imm: u16 = Self::get_bits_u16(num, 3..5, 1);
        imm |= Self::get_bits_u16(num, 10..12, 3);
        imm |= Self::get_bits_u16(num, 2..3, 5);
        imm |= Self::get_bits_u16(num, 5..7, 6);
        let sign = Self::get_bits_u16(num, 12..13, 0) == 1;
        if sign {
            (imm | MASK_SIGN) as i16 as u32
        } else {
            imm as u32
        }
    }

    fn calc_imm_cj(num: u16) -> u32 {
        const MASK_SIGN: u16 = 0xF800;
        let mut imm: u16 = Self::get_bits_u16(num, 3..6, 1);
        imm |= Self::get_bits_u16(num, 11..12, 4);
        imm |= Self::get_bits_u16(num, 2..3, 5);
        imm |= Self::get_bits_u16(num, 6..7, 7);
        imm |= Self::get_bits_u16(num, 7..8, 6);
        imm |= Self::get_bits_u16(num, 9..11, 8);
        imm |= Self::get_bits_u16(num, 8..9, 10);
        let sign = Self::get_bits_u16(num, 12..13, 0) == 1;
        if sign {
            (imm | MASK_SIGN) as i16 as u32
        } else {
            imm as u32
        }
    }

    fn calc_imm_b(num: u32) -> u32 {
        const MASK_SIGN: u32 = 0xFFFFF000;
        let mut imm = Self::get_bits_u32(num, 8..12, 1);
        imm |= Self::get_bits_u32(num, 25..31, 5);
        imm |= Self::get_bits_u32(num, 7..8, 11);
        let sign = Self::get_bits_u32(num, 31..32, 0) == 1;
        if sign {
            imm | MASK_SIGN
        } else {
            imm
        }
    }

    fn calc_imm_j(num: u32) -> u32 {
        const MASK_SIGN: u32 = 0xFFF00000;
        let mut imm = Self::get_bits_u32(num, 21..25, 1);
        imm |= Self::get_bits_u32(num, 25..31, 5);
        imm |= Self::get_bits_u32(num, 20..21, 11);
        imm |= Self::get_bits_u32(num, 12..20, 12);
        let sign = Self::get_bits_u32(num, 31..32, 0) == 1;
        if sign {
            imm | MASK_SIGN
        } else {
            imm
        }
    }

    fn calc_imm_i(num: u32) -> u32 {
        const MASK_SIGN: u32 = 0xFFFFF800;
        let imm = Self::get_bits_u32(num, 20..31, 0);
        let sign = Self::get_bits_u32(num, 31..32, 0) == 1;
        if sign {
            imm | MASK_SIGN
        } else {
            imm
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::disassembler::BinaryInstruction::{Bit16, Bit32};
    use crate::disassembler::*;

    const DEFAULT_INSTR: Instruction = Instruction {
        name: Name::mret,
        is_rs1_zero: false,
        size: 4,
        is_branch: false,
        imm: None,
    };

    #[test_case]
    fn mret() {
        let bin = Bit32(0x30200073);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                name: Name::mret,
                ..DEFAULT_INSTR
            }
        )
    }

    #[test_case]
    fn sret() {
        let bin = Bit32(0x10200073);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                name: Name::sret,
                ..DEFAULT_INSTR
            }
        );
    }

    #[test_case]
    fn fence() {
        let bin = Bit32(0x0ff0000f);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                name: Name::fence,
                ..DEFAULT_INSTR
            }
        );
    }

    #[test_case]
    fn sfence_vma() {
        let bin = Bit32(0x12010073);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                name: Name::sfence_vma,
                ..DEFAULT_INSTR
            }
        )
    }

    #[test_case]
    fn wfi() {
        let bin = Bit32(0x10500073);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                name: Name::wfi,
                ..DEFAULT_INSTR
            }
        )
    }

    #[test_case]
    fn ecall() {
        let bin = Bit32(0x00000073);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                name: Name::ecall,
                ..DEFAULT_INSTR
            }
        )
    }

    #[test_case]
    fn ebreak() {
        let bin = Bit32(0x00100073);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                name: Name::ebreak,
                ..DEFAULT_INSTR
            }
        )
    }

    #[test_case]
    fn fence_i() {
        let bin = Bit32(0x0000100f);
        assert_eq!(Instruction::from_binary(&bin), Instruction {
            name: Name::fence_i,
            ..DEFAULT_INSTR
        })
    }

    #[test_case]
    fn beq() {
        let bin = Bit32(0xaa360b63);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                name: Name::beq,
                is_branch: true,
                imm: Some(-3402i32 as u32),
                ..DEFAULT_INSTR
            }
        )
    }

    #[test_case]
    fn bne() {
        let bin = Bit32(0xf4361963);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                name: Name::bne,
                is_branch: true,
                imm: Some(-2222i32 as u32),
                ..DEFAULT_INSTR
            }
        )
    }

    #[test_case]
    fn blt() {
        let bin = Bit32(0x00004663);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                name: Name::blt,
                is_branch: true,
                imm: Some(12),
                ..DEFAULT_INSTR
            }
        )
    }

    #[test_case]
    fn bge() {
        let bin = Bit32(0x845f5fe3);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                name: Name::bge,
                is_branch: true,
                imm: Some(-1954i32 as u32),
                ..DEFAULT_INSTR
            }
        )
    }

    #[test_case]
    fn bltu() {
        let bin = Bit32(0x7f406fe3);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                name: Name::bltu,
                is_branch: true,
                imm: Some(4094),
                ..DEFAULT_INSTR
            }
        )
    }

    #[test_case]
    fn bgeu() {
        let bin = Bit32(0x01467063);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                name: Name::bgeu,
                is_branch: true,
                imm: Some(0),
                ..DEFAULT_INSTR
            }
        )
    }

    #[test_case]
    fn c_beqz() {
        let bin = Bit16(0xca4d);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                name: Name::c_beqz,
                is_branch: true,
                size: 2,
                imm: Some(178),
                is_rs1_zero: false,
            }
        )
    }

    #[test_case]
    fn c_benz() {
        let bin = Bit16(0xe6cd);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                name: c_bnez,
                is_branch: true,
                imm: Some(170),
                size: 2,
                is_rs1_zero: false
            }
        )
    }

    #[test_case]
    fn jal() {
        let bin = Bit32(0x1030d66f);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                name: Name::jal,
                is_branch: false, // TODO fixme????
                imm: Some(55554),
                ..DEFAULT_INSTR
            }
        )
    }

    #[test_case]
    fn c_j() {
        let bin = Bit16(0xab91);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                name: Name::c_j,
                is_branch: false,
                imm: Some(1364),
                is_rs1_zero: false,
                size: 2
            }
        )
    }

    #[test_case]
    fn c_jal() {
        let bin = Bit16(0x39f5);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                name: Name::c_jal,
                is_branch: false,
                imm: Some(-772i16 as u32),
                is_rs1_zero: false,
                size: 2
            }
        )
    }

    #[test_case]
    fn c_jr() {
        let bin = Bit16(0x8602);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                name: Name::c_jr,
                is_branch: false,
                imm: None,
                is_rs1_zero: false,
                size: 2
            }
        )
    }

    #[test_case]
    fn c_jalr() {
        let bin = Bit16(0x9f82);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                name: Name::c_jalr,
                is_branch: false,
                imm: None,
                is_rs1_zero: false,
                size: 2
            }
        )
    }

    #[test_case]
    fn c_ebreak() {
        let bin = Bit16(0x9002);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                name: Name::c_ebreak,
                is_branch: false,
                imm: None,
                is_rs1_zero: false,
                size: 2
            }
        )
    }

    #[test_case]
    fn jalr() {
        let bin = Bit32(0x66168867);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                name: Name::jalr,
                imm: None,
                ..DEFAULT_INSTR
            }
        )
    }

    #[test_case]
    fn jalr_rs1_zero() {
        let bin = Bit32(0x66100fe7);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                name: Name::jalr,
                imm: Some(1633),
                is_rs1_zero: true,
                ..DEFAULT_INSTR
            }
        )
    }
}
