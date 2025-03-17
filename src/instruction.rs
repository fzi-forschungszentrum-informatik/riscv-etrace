// Copyright (C) 2024 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

use core::fmt;
use core::fmt::Formatter;
use core::ops::Range;

pub mod format;

#[cfg(test)]
mod tests;

use Kind::*;
use OpCode::*;

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

/// The bits from which instructions can be disassembled.
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
    Auipc = 0b0010111,
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
            x if x == Auipc as u32 => Auipc,
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
pub enum Kind {
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
    beq(format::TypeB),
    bne(format::TypeB),
    blt(format::TypeB),
    bge(format::TypeB),
    bltu(format::TypeB),
    bgeu(format::TypeB),
    // U
    auipc(format::TypeU),
    lui(format::TypeU),
    // CB
    c_beqz(format::TypeB),
    c_bnez(format::TypeB),
    // J
    jal(format::TypeJ),
    // CJ
    c_j(format::TypeJ),
    c_jal(format::TypeJ),
    // CU
    c_lui(format::TypeU),
    // CR
    c_jr(format::TypeR),
    c_jalr(format::TypeR),
    c_ebreak,
    // I
    jalr(format::TypeI),
}

impl Kind {
    /// Determine the branch target
    ///
    /// If [Self] refers to a branch instruction, this fn returns the immediate,
    /// which is the branch target relative to this instruction. Returns `None`
    /// if [Self] does not refer to a (known) branch instruction. Jump
    /// instructions are not considered branch instructions.
    pub fn branch_target(self) -> Option<i16> {
        match self {
            Self::c_beqz(d) => Some(d.imm),
            Self::c_bnez(d) => Some(d.imm),
            Self::beq(d) => Some(d.imm),
            Self::bne(d) => Some(d.imm),
            Self::blt(d) => Some(d.imm),
            Self::bge(d) => Some(d.imm),
            Self::bltu(d) => Some(d.imm),
            Self::bgeu(d) => Some(d.imm),
            _ => None,
        }
    }

    /// Determine the inferable jump target
    ///
    /// If [Self] refers to a jump instruction that in itself determines the
    /// jump target, this fn returns that target relative to this instruction.
    /// Returns `None` if [Self] does not refer to a (known) jump instruction or
    /// if the branch target cannot be inferred based on the instruction alone.
    ///
    /// For example, a `jalr` instruciton's target will never be considered
    /// inferable unless the source register is the `zero` register, even if it
    /// is preceeded directly by `auipc` and `addi` instructions defining a
    /// constant jump target.
    ///
    /// Branch instructions are not considered jump instructions.
    pub fn inferable_jump_target(self) -> Option<i32> {
        match self {
            Self::jal(d) => Some(d.imm),
            Self::c_jal(d) => Some(d.imm),
            Self::c_j(d) => Some(d.imm),
            Self::jalr(format::TypeI { rs1: 0, imm, .. }) => Some(imm.into()),
            _ => None,
        }
    }

    /// Determine whether this instruction refers to an uninferable jump
    ///
    /// If [Self] refers to a jump instruction that in itself does not determine
    /// the (relative) jump target, this fn returns the information neccessary
    /// to determine the target in the form of a register number (first tuple
    /// element) and an offset (decond tuple element). The jump target is
    /// computed by adding the offset to the contents of the denoted register.
    ///
    /// Note that a `jalr` instruciton's target will always be considered
    /// uninferable unless the source register is the `zero` register, even if
    /// it is preceeded directly by `auipc` and `addi` instructions defining a
    /// constant jump target. However, callers may be able to infer the jump
    /// target in such situations using statically determined register values.
    ///
    /// Branch instructions are not considered jump instructions.
    pub fn uninferable_jump(self) -> Option<(format::Register, i16)> {
        match self {
            Self::c_jalr(d) => Some((d.rs1, 0)),
            Self::c_jr(d) => Some((d.rs1, 0)),
            Self::jalr(d) => Some((d.rs1, d.imm)),
            _ => None,
        }
        .filter(|(r, _)| *r != 0)
    }

    /// Determine whether this instruction returns from a trap
    ///
    /// Returns true if [Self] refers to one of the (known) special instructions
    /// that return from a trap.
    pub fn is_return_from_trap(self) -> bool {
        matches!(self, Self::uret | Self::sret | Self::mret | Self::dret)
    }

    /// Determine whether this instruction causes an uninferable discontinuity
    ///
    /// Returns true if [Self] refers to an instruction that causes a (PC)
    /// discontinuity with a target that can not be inferred from the
    /// instruction alone. This is the case if the instruction is either
    /// * an [uninferable jump][Self::uninferable_jump],
    /// * a [return from trap][Self::is_return_from_trap] or
    /// * an `ecall` or `ebreak` (compressed or uncompressed).
    pub fn is_uninferable_discon(self) -> bool {
        self.uninferable_jump().is_some()
            || self.is_return_from_trap()
            || matches!(self, Self::ecall | Self::ebreak | Self::c_ebreak)
    }

    /// Determine whether this instruction can be considered a function call
    ///
    /// Returns true if [Self] refers to an instruction that we consider a
    /// function call, that is a jump-and-link instruction with `ra` (the return
    /// address register) as `rd`.
    pub fn is_call(self) -> bool {
        matches!(
            self,
            Self::jalr(format::TypeI { rd: 1, .. })
                | Self::c_jalr(_)
                | Self::jal(format::TypeJ { rd: 1, .. })
                | Self::c_jal(_)
        )
    }

    /// Determine whether this instruction can be considered a function return
    ///
    /// Returns true if [Self] refers to an instruction that we consider a
    /// function return, that is a jump register instruction with `ra` (the
    /// return address register) as `rs1`.
    pub fn is_return(self) -> bool {
        matches!(
            self,
            Self::jalr(format::TypeI { rd: 0, rs1: 1, .. })
                | Self::c_jr(format::TypeR { rs1: 1, .. })
        )
    }

    /// Decode a 32bit ("normal") instruction
    ///
    /// Returns an instruction if it can be decoded, that is if that instruction
    /// is known. As only a small part of all RISC-V instruction is relevant, we
    /// don't consider unknown instructions an error.
    #[allow(clippy::unusual_byte_groupings)]
    pub fn decode_32(insn: u32) -> Option<Self> {
        let funct3 = (insn >> 12) & 0x7;

        match OpCode::from(insn) {
            OpCode::MiscMem => match funct3 {
                0b000 => Some(Self::fence),
                0b001 => Some(Self::fence_i),
                _ => None,
            },
            OpCode::Lui => Some(Self::lui(insn.into())),
            OpCode::Auipc => Some(Self::auipc(insn.into())),
            OpCode::Branch => match funct3 {
                0b000 => Some(Self::beq(insn.into())),
                0b001 => Some(Self::bne(insn.into())),
                0b100 => Some(Self::blt(insn.into())),
                0b101 => Some(Self::bge(insn.into())),
                0b110 => Some(Self::bltu(insn.into())),
                0b111 => Some(Self::bgeu(insn.into())),
                _ => None,
            },
            OpCode::Jalr => Some(Self::jalr(insn.into())),
            OpCode::Jal => Some(Self::jal(insn.into())),
            OpCode::System => match insn >> 7 {
                0b000000000000_00000_000_00000 => Some(Self::ecall),
                0b000000000001_00000_000_00000 => Some(Self::ebreak),
                0b000100000010_00000_000_00000 => Some(Self::sret),
                0b001100000010_00000_000_00000 => Some(Self::mret),
                0b000100000101_00000_000_00000 => Some(Self::wfi),
                _ if (insn >> 25) == 0b0001001 => Some(Self::sfence_vma),
                _ => None,
            },
            _ => None,
        }
    }

    /// Decode a 16bit ("compressed") instruction
    ///
    /// Returns an instruction if it can be decoded, that is if that instruction
    /// is known. As only a small part of all RISC-V instruction is relevant, we
    /// don't consider unknown instructions an error.
    pub fn decode_16(insn: u16) -> Option<Self> {
        let op = insn & 0x3;
        let func3 = insn >> 13;
        match (op, func3) {
            (0b01, 0b001) => Some(Self::c_jal(insn.into())),
            (0b01, 0b011) => {
                let data = format::TypeU::from(insn);
                if data.rd != 0 || data.rd != 2 {
                    Some(Self::c_lui(data))
                } else {
                    None
                }
            }
            (0x01, 0b101) => Some(Self::c_j(insn.into())),
            (0x01, 0b110) => Some(Self::c_beqz(insn.into())),
            (0x01, 0b111) => Some(Self::c_bnez(insn.into())),
            (0b10, 0b100) => {
                let data = format::TypeR::from(insn);
                let bit12 = (insn >> 12) & 0x1;
                match (bit12, data.rs1, data.rs2) {
                    (0, r, 0) if r != 0 => Some(Self::c_jr(data)),
                    (1, r, 0) if r != 0 => Some(Self::c_jalr(data)),
                    (1, 0, 0) => Some(Self::c_ebreak),
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

/// Represents the possible byte length of single RISC-V [Instruction].
/// It is either 4 or 2 bytes.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum InstructionSize {
    Compressed = 2,
    Normal = 4,
}

impl Default for InstructionSize {
    fn default() -> Self {
        Self::Normal
    }
}

/// Defines a single RISC-V instruction
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Instruction {
    pub size: InstructionSize,
    /// If the instruction was parsed, the name is always available.
    pub kind: Option<Kind>,
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
            kind: None,
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
        if let Some(name) = self.kind {
            matches!(name, jal(_) | c_jal(_) | c_j(_))
                || (matches!(name, jalr(_)) && self.is_rs1_zero)
        } else {
            false
        }
    }

    pub fn is_uninferable_jump(&self) -> bool {
        if let Some(name) = self.kind {
            matches!(name, c_jalr(_) | c_jr(_)) || (matches!(name, jalr(_)) && !self.is_rs1_zero)
        } else {
            false
        }
    }

    #[cfg(not(feature = "tracing_v1"))]
    pub fn is_return_from_trap(&self) -> bool {
        if let Some(name) = self.kind {
            name == sret || name == mret || name == dret
        } else {
            false
        }
    }

    #[cfg(not(feature = "tracing_v1"))]
    pub fn is_uninferable_discon(&self) -> bool {
        if let Some(name) = self.kind {
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
        if let Some(name) = self.kind {
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
        if let Some(name) = self.kind {
            matches!(
                name,
                jalr(format::TypeI { rd: 1, .. })
                    | c_jalr(_)
                    | jal(format::TypeJ { rd: 1, .. })
                    | c_jal(_)
            )
        } else {
            false
        }
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
            Lui => lui(num.into()),
            Auipc => auipc(num.into()),
            Branch => match funct3 {
                0b000 => beq(num.into()),
                0b001 => bne(num.into()),
                0b100 => blt(num.into()),
                0b101 => bge(num.into()),
                0b110 => bltu(num.into()),
                0b111 => bgeu(num.into()),
                _ => return ignored,
            },
            Jalr => {
                is_rs1_zero = 0 == Self::rs1(num);
                jalr(num.into())
            }
            Jal => jal(num.into()),
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
            kind: Some(name),
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
                0b001 => c_jal(num.into()),
                0b011 => {
                    if rd != 0 || rd != 2 {
                        c_lui(num.into())
                    } else {
                        return ignored;
                    }
                }
                0b101 => c_j(num.into()),
                0b110 => c_beqz(num.into()),
                0b111 => c_bnez(num.into()),
                _ => return ignored,
            },
            0b10 => {
                let bit12 = Self::bit12(num);
                let rs2 = Self::c_rs2(num);
                if funct3 != 0b100 {
                    return ignored;
                } else if !bit12 && rs1 != 0 && rs2 == 0 {
                    c_jr(num.into())
                } else if bit12 && rs1 == 0 && rs2 == 0 {
                    c_ebreak
                } else if bit12 && rs1 != 0 && rs2 == 0 {
                    c_jalr(num.into())
                } else {
                    return ignored;
                }
            }
            _ => return ignored,
        };
        let is_branch = matches!(name, c_beqz(_) | c_bnez(_));
        Instruction {
            size,
            is_branch,
            is_rs1_zero: false,
            kind: Some(name),
            imm: Self::calc_compressed_imm(name, is_branch, num),
            #[cfg(feature = "implicit_return")]
            rs1: rs1 as u32,
            #[cfg(feature = "implicit_return")]
            rd: rd as u32,
        }
    }

    fn calc_imm(name: Kind, is_rs1_zero: bool, is_branch: bool, num: u32) -> Option<i32> {
        if is_branch {
            Some(Self::calc_imm_b(num))
        } else {
            match name {
                lui(_) => Some(Self::calc_imm_u(num)),
                auipc(_) => Some(Self::calc_imm_u(num)),
                jal(_) => Some(Self::calc_imm_j(num)),
                jalr(_) if is_rs1_zero => Some(Self::calc_imm_i(num)),
                _ => None,
            }
        }
    }

    fn calc_compressed_imm(name: Kind, is_branch: bool, num: u16) -> Option<i32> {
        if is_branch {
            Some(Self::calc_imm_cb(num))
        } else {
            match name {
                c_lui(_) => {
                    let imm = Self::calc_imm_cu(num);
                    if imm == 0 {
                        panic!("riscv spec: imm should not be zero for c.lui")
                    } else {
                        Some(imm)
                    }
                }
                c_j(_) | c_jal(_) => Some(Self::calc_imm_cj(num)),
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

impl Default for Instruction {
    fn default() -> Self {
        Self::ignored(Default::default())
    }
}
