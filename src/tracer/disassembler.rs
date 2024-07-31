// Copyright (C) 2024 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

use crate::tracer::disassembler::Name::*;
use crate::tracer::disassembler::OpCode::*;

use core::fmt;
use core::fmt::Formatter;
use core::ops::Range;

/// A segment of executable RISC-V code which is executed on the traced system.
/// `first_addr` is the same address the encoder uses for instructions in this segment.
/// No instruction in this segment has a larger address than `last_addr`.
/// `mem` is a slice of `[u8; last_addr - first_addr]` bytes containing the instructions.
#[derive(Copy, Clone)]
pub struct Segment<'a> {
    pub first_addr: u64,
    pub last_addr: u64,
    pub mem: &'a [u8],
}

impl fmt::Debug for Segment<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "Segment {{ first_addr {:#0x}, last_addr: {:#0x} }}",
            self.first_addr, self.last_addr
        ))
    }
}

impl<'a> Segment<'a> {
    pub fn new(first_addr: u64, last_addr: u64, mem: &'a [u8]) -> Self {
        assert!(first_addr < last_addr);
        assert_eq!(
            usize::try_from(last_addr - first_addr).unwrap(),
            mem.len(),
            "addr length does not equal memory slice length"
        );
        Segment {
            first_addr,
            last_addr,
            mem,
        }
    }

    /// Returns true if `vaddr_start <= addr <= vaddr_end`.
    pub fn contains(&self, addr: u64) -> bool {
        self.first_addr <= addr && addr <= self.last_addr
    }
}

#[derive(Copy, Clone, Debug)]
pub enum InstructionBits {
    Bit32(u32),
    Bit16(u16),
}

impl InstructionBits {
    pub(crate) fn read_binary(address: u64, segment: &Segment) -> Result<Self, [u8; 4]> {
        let pointer = usize::try_from(address - segment.first_addr).unwrap();
        let bytes = &segment.mem[pointer..pointer + 4];
        if (bytes[0] & 0x3) != 0x3 {
            Ok(InstructionBits::Bit16(u16::from_le_bytes(
                bytes[0..2].try_into().unwrap(),
            )))
        } else if (bytes[0] & 0x1F) >= 0x3 && (bytes[0] & 0x1F) < 0x1F {
            Ok(InstructionBits::Bit32(u32::from_le_bytes(
                bytes.try_into().unwrap(),
            )))
        } else {
            Err(bytes.try_into().unwrap())
        }
    }
}

#[repr(u32)]
#[derive(Eq, PartialEq)]
enum OpCode {
    MiscMem = 0b0001111,
    Lui = 0b0110111,
    Aupic = 0b0010111,
    Branch = 0b1100011,
    Jalr = 0b1100111,
    Jal = 0b1101111,
    System = 0b1110011,
    Ignored,
}

impl From<u32> for OpCode {
    fn from(value: u32) -> Self {
        const MASK: u32 = 0x7F;
        match value & MASK {
            x if x == Aupic as u32 => Aupic,
            x if x == Lui as u32 => Lui,
            x if x == MiscMem as u32 => MiscMem,
            x if x == Branch as u32 => Branch,
            x if x == Jalr as u32 => Jalr,
            x if x == Jal as u32 => Jal,
            x if x == System as u32 => System,
            _ => Ignored,
        }
    }
}

/// A list of the name of all control flow changing instructions the tracing algorithm needs to know.  
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Name {
    // SYS (R)
    mret,
    sret,
    uret, // TODO not parsed, uret is legacy
    dret, // TODO not parsed, dret is only in rc
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
    // U
    aupic,
    lui,
    // CB
    c_beqz,
    c_bnez,
    // J
    jal,
    // CJ
    c_j,
    c_jal,
    // CU
    c_lui,
    // CR
    c_jr,
    c_jalr,
    c_ebreak,
    // I
    jalr,
}

/// Represents the possible byte length of single RISC-V [Instruction].
/// It is either 4 or 2 bytes.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum InstructionSize {
    Compressed = 2,
    Normal = 4,
}

/// Defines a single RISC-V instruction. If the instruction was parsed (see [Name] for a list of
/// instructions which are parsed) additional fields and information about the instruction such as
/// the immediate may be available.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Instruction {
    pub size: InstructionSize,
    /// If the instruction was parsed, the name is always available.
    pub name: Option<Name>,
    /// Defaults to `false`. Only parsed for `jalr`. For other instructions a value of
    /// `false` has no relation to RS1 and whether it is zero.
    pub is_rs1_zero: bool,
    /// Only true for branching and compressed branching instructions. If the instruction is not
    /// branching (not a B or compressed B type instruction, this even excludes control flow
    /// changing instructions such as `jalr`) `is_branch` is `false`.
    pub is_branch: bool,
    /// Only parsed if the immediate is necessary for the tracing algorithm, else `None`.
    pub imm: Option<i32>,
    #[cfg(feature = "implicit_return")]
    /// Only parsed if implicit returns are enabled.
    pub rs1: u32,
    #[cfg(feature = "implicit_return")]
    /// Only parsed if implicit returns are enabled.
    pub rd: u32,
}

impl Instruction {
    fn ignored(size: InstructionSize) -> Self {
        Instruction {
            size,
            name: None,
            is_rs1_zero: false,
            is_branch: false,
            imm: None,
            #[cfg(feature = "implicit_return")]
            rs1: 0,
            #[cfg(feature = "implicit_return")]
            rd: 0
        }
    }

    pub fn is_inferable_jump(&self) -> bool {
        if let Some(name) = self.name {
            name == jal || name == c_jal || name == c_j || (name == jalr && self.is_rs1_zero)
        } else {
            false
        }
    }

    pub fn is_uninferable_jump(&self) -> bool {
        if let Some(name) = self.name {
            name == c_jalr || name == c_jr || (name == jalr && !self.is_rs1_zero)
        } else {
            false
        }
    }

    #[cfg(not(feature = "tracing_v1"))]
    pub fn is_return_from_trap(&self) -> bool {
        if let Some(name) = self.name {
            name == sret || name == mret || name == dret
        } else {
            false
        }
    }

    #[cfg(not(feature = "tracing_v1"))]
    pub fn is_uninferable_discon(&self) -> bool {
        if let Some(name) = self.name {
            self.is_uninferable_jump()
                || self.is_return_from_trap()
                || name == ecall
                || name == ebreak
                || name == c_ebreak
        } else {
            false
        }
    }

    #[cfg(feature = "tracing_v1")]
    pub fn is_uninferable_discon(&self) -> bool {
        if let Some(name) = self.name {
            self.is_uninferable_jump()
                || name == uret
                || name == sret
                || name == mret
                || name == dret
                || name == ecall
                || name == ebreak
                || name == c_ebreak
        } else {
            false
        }
    }

    #[cfg(feature = "implicit_return")]
    pub fn is_call(&self) -> bool {
        if let Some(name) = self.name {
            if (name == jalr && self.rd == 1)
                || name == c_jalr
                || (name == jal && self.rd == 1)
                || name == c_jal {
                return true
            }
        }
        false
    }

    pub(crate) fn from_binary(bin_instr: &InstructionBits) -> Self {
        match bin_instr {
            InstructionBits::Bit32(num) => Self::parse_bin_instr(*num),
            InstructionBits::Bit16(num) => Self::parse_compressed_instr(*num),
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
        let size = InstructionSize::Normal;
        let ignored = Instruction::ignored(size);

        let mut is_rs1_zero = false;
        let opcode = OpCode::from(num);

        let funct3 = Self::funct3(num);
        let rd = Self::rd(num);
        let rs1 = Self::rs1(num);

        let name = match opcode {
            MiscMem => match funct3 {
                0b000 => fence,
                0b001 => fence_i,
                _ => return ignored,
            },
            Lui => lui,
            Aupic => aupic,
            Branch => match funct3 {
                0b000 => beq,
                0b001 => bne,
                0b100 => blt,
                0b101 => bge,
                0b110 => bltu,
                0b111 => bgeu,
                _ => return ignored,
            },
            Jalr => {
                is_rs1_zero = 0 == Self::rs1(num);
                jalr
            }
            Jal => jal,
            System => {
                if rd != 0 || funct3 != 0 {
                    return ignored;
                } else {
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
                        return ignored;
                    }
                }
            }
            Ignored => return ignored,
        };
        Instruction {
            size,
            name: Some(name),
            is_rs1_zero,
            is_branch: opcode == Branch,
            imm: Self::calc_imm(name, is_rs1_zero, opcode == Branch, num),
            #[cfg(feature = "implicit_return")]
            rs1,
            #[cfg(feature = "implicit_return")]
            rd,
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
        let size = InstructionSize::Compressed;
        let ignored = Instruction::ignored(size);

        let op = Self::c_op(num);
        let funct3 = Self::c_funct3(num);
        let rs1 = Self::c_rs1(num);
        let rd = Self::c_rs1(num);

        let name = match op {
            0b01 => match funct3 {
                0b001 => c_jal,
                0b011 => {
                    if rd != 0 || rd != 2 {
                        c_lui
                    } else {
                        return ignored;
                    }
                }
                0b101 => c_j,
                0b110 => c_beqz,
                0b111 => c_bnez,
                _ => return ignored,
            },
            0b10 => {
                let bit12 = Self::bit12(num);
                let rs2 = Self::c_rs2(num);
                if funct3 != 0b100 {
                    return ignored;
                } else if !bit12 && rs1 != 0 && rs2 == 0 {
                    c_jr
                } else if bit12 && rs1 == 0 && rs2 == 0 {
                    c_ebreak
                } else if bit12 && rs1 != 0 && rs2 == 0 {
                    c_jalr
                } else {
                    return ignored;
                }
            }
            _ => return ignored,
        };
        let is_branch = name == c_beqz || name == c_bnez;
        Instruction {
            size,
            is_branch,
            is_rs1_zero: false,
            name: Some(name),
            imm: Self::calc_compressed_imm(name, is_branch, num),
            #[cfg(feature = "implicit_return")]
            rs1: rs1 as u32,
            #[cfg(feature = "implicit_return")]
            rd: rd as u32,
        }
    }

    fn calc_imm(name: Name, is_rs1_zero: bool, is_branch: bool, num: u32) -> Option<i32> {
        if is_branch {
            Some(Self::calc_imm_b(num))
        } else {
            match name {
                lui => Some(Self::calc_imm_u(num)),
                aupic => Some(Self::calc_imm_u(num)),
                jal => Some(Self::calc_imm_j(num)),
                jalr if is_rs1_zero => Some(Self::calc_imm_i(num)),
                _ => None,
            }
        }
    }

    fn calc_compressed_imm(name: Name, is_branch: bool, num: u16) -> Option<i32> {
        if is_branch {
            Some(Self::calc_imm_cb(num))
        } else {
            match name {
                c_lui => {
                    let imm = Self::calc_imm_cu(num);
                    if imm == 0 {
                        panic!("riscv spec: imm should not be zero for c.lui")
                    } else {
                        Some(imm)
                    }
                }
                c_j | c_jal => Some(Self::calc_imm_cj(num)),
                _ => None,
            }
        }
    }

    fn mask_u32(r: &Range<i32>) -> u32 {
        ((1_u32 << r.len()) - 1) << r.start
    }

    fn mask_u16(r: &Range<i32>) -> u16 {
        ((1_u16 << r.len()) - 1) << r.start
    }

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

    fn calc_imm_cb(num: u16) -> i32 {
        const MASK_SIGN: u16 = 0xFF80;
        let mut imm: u16 = Self::get_bits_u16(num, 3..5, 1);
        imm |= Self::get_bits_u16(num, 10..12, 3);
        imm |= Self::get_bits_u16(num, 2..3, 5);
        imm |= Self::get_bits_u16(num, 5..7, 6);
        let sign = Self::get_bits_u16(num, 12..13, 0) == 1;
        if sign {
            (imm | MASK_SIGN) as i16 as i32
        } else {
            imm as i32
        }
    }

    fn calc_imm_cj(num: u16) -> i32 {
        const MASK_SIGN: u16 = 0xF800;
        let mut imm = Self::get_bits_u16(num, 3..6, 1);
        imm |= Self::get_bits_u16(num, 11..12, 4);
        imm |= Self::get_bits_u16(num, 2..3, 5);
        imm |= Self::get_bits_u16(num, 6..7, 7);
        imm |= Self::get_bits_u16(num, 7..8, 6);
        imm |= Self::get_bits_u16(num, 9..11, 8);
        imm |= Self::get_bits_u16(num, 8..9, 10);
        let sign = Self::get_bits_u16(num, 12..13, 0) == 1;
        if sign {
            (imm | MASK_SIGN) as i16 as i32
        } else {
            imm as i32
        }
    }

    fn calc_imm_cu(num: u16) -> i32 {
        const MASK_SIGN: u16 = 0xFFF0;
        let imm = Self::get_bits_u16(num, 2..7, 0);
        let sign = Self::get_bits_u16(num, 12..13, 0) == 1;
        if sign {
            (imm | MASK_SIGN) as i16 as i32
        } else {
            imm as i32
        }
    }

    fn calc_imm_b(num: u32) -> i32 {
        const MASK_SIGN: u32 = 0xFFFFF000;
        let mut imm = Self::get_bits_u32(num, 8..12, 1);
        imm |= Self::get_bits_u32(num, 25..31, 5);
        imm |= Self::get_bits_u32(num, 7..8, 11);
        let sign = Self::get_bits_u32(num, 31..32, 0) == 1;
        if sign {
            (imm | MASK_SIGN) as i32
        } else {
            imm as i32
        }
    }

    fn calc_imm_j(num: u32) -> i32 {
        const MASK_SIGN: u32 = 0xFFF00000;
        let mut imm = Self::get_bits_u32(num, 21..25, 1);
        imm |= Self::get_bits_u32(num, 25..31, 5);
        imm |= Self::get_bits_u32(num, 20..21, 11);
        imm |= Self::get_bits_u32(num, 12..20, 12);
        let sign = Self::get_bits_u32(num, 31..32, 0) == 1;
        if sign {
            (imm | MASK_SIGN) as i32
        } else {
            imm as i32
        }
    }

    fn calc_imm_i(num: u32) -> i32 {
        const MASK_SIGN: u32 = 0xFFFFF800;
        let imm = Self::get_bits_u32(num, 20..31, 0);
        let sign = Self::get_bits_u32(num, 31..32, 0) == 1;
        if sign {
            (imm | MASK_SIGN) as i32
        } else {
            imm as i32
        }
    }

    fn calc_imm_u(num: u32) -> i32 {
        const MASK_SIGN: u32 = 0xFFF80000;
        let imm = Self::get_bits_u32(num, 12..31, 0);
        let sign = Self::get_bits_u32(num, 31..32, 0) == 1;
        if sign {
            (imm | MASK_SIGN) as i32
        } else {
            imm as i32
        }
    }
}

#[cfg(feature = "cache")]
const INSTRUCTION_CACHE_LEN: usize = 6;

#[cfg(feature = "cache")]
#[derive(Copy, Clone, Debug)]
pub struct InstructionCache {
    pub addresses: [Option<u64>; INSTRUCTION_CACHE_LEN],
    pub instructions: [Option<Instruction>; INSTRUCTION_CACHE_LEN],
}

#[cfg(feature = "cache")]
impl<'a> InstructionCache {
    pub(crate) fn new() -> Self {
        InstructionCache {
            addresses: [None; INSTRUCTION_CACHE_LEN],
            instructions: [None; INSTRUCTION_CACHE_LEN],
        }
    }

    pub(crate) fn write(&mut self, addr: u64, instr: Instruction) {
        for i in 0..self.addresses.len() - 1 {
            self.addresses[i] = self.addresses[i + 1];
            self.instructions[i] = self.instructions[i + 1];
        }
        self.addresses[INSTRUCTION_CACHE_LEN - 1] = Some(addr);
        self.instructions[INSTRUCTION_CACHE_LEN - 1] = Some(instr);
    }

    pub fn get(&self, k: u64) -> Option<&Instruction> {
        for (i, opt) in self.addresses.iter().enumerate() {
            if let Some(addr) = opt {
                if *addr == k {
                    return self.instructions[i].as_ref();
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::tracer::disassembler::InstructionBits::{Bit16, Bit32};
    use crate::tracer::disassembler::*;

    #[test]
    fn mret() {
        let bin = Bit32(0x30200073);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Normal,
                name: Some(Name::mret),
                is_rs1_zero: false,
                is_branch: false,
                imm: None,
            }
        )
    }

    #[test]
    fn sret() {
        let bin = Bit32(0x10200073);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Normal,
                name: Some(Name::sret),
                is_rs1_zero: false,
                is_branch: false,
                imm: None,
            }
        );
    }

    #[test]
    fn fence() {
        let bin = Bit32(0x0ff0000f);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Normal,
                name: Some(Name::fence),
                is_rs1_zero: false,
                is_branch: false,
                imm: None,
            }
        )
    }

    #[test]
    fn sfence_vma() {
        let bin = Bit32(0x12010073);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Normal,
                name: Some(Name::sfence_vma),
                is_rs1_zero: false,
                is_branch: false,
                imm: None,
            }
        )
    }

    #[test]
    fn wfi() {
        let bin = Bit32(0x10500073);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Normal,
                name: Some(Name::wfi),
                is_rs1_zero: false,
                is_branch: false,
                imm: None,
            }
        )
    }

    #[test]
    fn ecall() {
        let bin = Bit32(0x00000073);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Normal,
                name: Some(Name::ecall),
                is_rs1_zero: false,
                is_branch: false,
                imm: None,
            }
        )
    }

    #[test]
    fn ebreak() {
        let bin = Bit32(0x00100073);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Normal,
                name: Some(Name::ebreak),
                is_rs1_zero: false,
                is_branch: false,
                imm: None,
            }
        )
    }

    #[test]
    fn fence_i() {
        let bin = Bit32(0x0000100f);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Normal,

                name: Some(Name::fence_i),
                is_rs1_zero: false,
                is_branch: false,
                imm: None,
            }
        )
    }

    #[test]
    fn beq() {
        let bin = Bit32(0xaa360b63);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Normal,
                name: Some(Name::beq),
                is_branch: true,
                imm: Some(-3402),
                is_rs1_zero: false,
            }
        )
    }

    #[test]
    fn bne() {
        let bin = Bit32(0xf4361963);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Normal,
                name: Some(Name::bne),
                is_branch: true,
                imm: Some(-2222),
                is_rs1_zero: false,
            }
        )
    }

    #[test]
    fn blt() {
        let bin = Bit32(0x00004663);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Normal,
                name: Some(Name::blt),
                is_branch: true,
                imm: Some(12),
                is_rs1_zero: false,
            }
        )
    }

    #[test]
    fn bge() {
        let bin = Bit32(0x845f5fe3);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Normal,
                name: Some(Name::bge),
                is_branch: true,
                imm: Some(-1954),
                is_rs1_zero: false,
            }
        )
    }

    #[test]
    fn bltu() {
        let bin = Bit32(0x7f406fe3);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Normal,
                name: Some(Name::bltu),
                is_branch: true,
                imm: Some(4094),
                is_rs1_zero: false,
            }
        )
    }

    #[test]
    fn bgeu() {
        let bin = Bit32(0x01467063);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Normal,
                name: Some(Name::bgeu),
                is_branch: true,
                imm: Some(0),
                is_rs1_zero: false,
            }
        )
    }

    #[test]
    fn c_beqz() {
        let bin = Bit16(0xca4d);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Compressed,
                name: Some(Name::c_beqz),
                is_branch: true,
                imm: Some(178),
                is_rs1_zero: false,
            }
        )
    }

    #[test]
    fn c_benz() {
        let bin = Bit16(0xe6cd);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Compressed,
                name: Some(c_bnez),
                is_branch: true,
                imm: Some(170),
                is_rs1_zero: false
            }
        )
    }

    #[test]
    fn auipc() {
        let bin = Bit32(0xf2ab3697);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Normal,
                name: Some(aupic),
                is_branch: false,
                imm: Some(-54605),
                is_rs1_zero: false,
            }
        )
    }

    #[test]
    fn lui() {
        let bin = Bit32(0xfff0f8b7);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Normal,
                name: Some(Name::lui),
                is_branch: false,
                imm: Some(-241),
                is_rs1_zero: false,
            }
        )
    }

    #[test]
    fn c_lui() {
        let bin = Bit16(0x7255);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Compressed,
                name: Some(Name::c_lui),
                is_branch: false,
                imm: Some(-11),
                is_rs1_zero: false,
            }
        )
    }

    #[test]
    fn jal() {
        let bin = Bit32(0x1030d66f);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Normal,
                name: Some(Name::jal),
                is_branch: false,
                imm: Some(55554),
                is_rs1_zero: false,
            }
        )
    }

    #[test]
    fn c_j() {
        let bin = Bit16(0xab91);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Compressed,
                name: Some(Name::c_j),
                is_branch: false,
                imm: Some(1364),
                is_rs1_zero: false,
            }
        )
    }

    #[test]
    fn c_jal() {
        let bin = Bit16(0x39f5);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Compressed,
                name: Some(Name::c_jal),
                is_branch: false,
                imm: Some(-772),
                is_rs1_zero: false,
            }
        )
    }

    #[test]
    fn c_jr() {
        let bin = Bit16(0x8602);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Compressed,
                name: Some(Name::c_jr),
                is_branch: false,
                imm: None,
                is_rs1_zero: false,
            }
        )
    }

    #[test]
    fn c_jalr() {
        let bin = Bit16(0x9f82);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Compressed,
                name: Some(Name::c_jalr),
                is_branch: false,
                imm: None,
                is_rs1_zero: false,
            }
        )
    }

    #[test]
    fn c_ebreak() {
        let bin = Bit16(0x9002);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Compressed,
                name: Some(Name::c_ebreak),
                is_branch: false,
                imm: None,
                is_rs1_zero: false,
            }
        )
    }

    #[test]
    fn jalr() {
        let bin = Bit32(0x66168867);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Normal,
                name: Some(Name::jalr),
                imm: None,
                is_rs1_zero: false,
                is_branch: false,
            }
        )
    }

    #[test]
    fn jalr_rs1_zero() {
        let bin = Bit32(0x66100fe7);
        assert_eq!(
            Instruction::from_binary(&bin),
            Instruction {
                size: InstructionSize::Normal,
                name: Some(Name::jalr),
                imm: Some(1633),
                is_rs1_zero: true,
                is_branch: false,
            }
        )
    }
}
