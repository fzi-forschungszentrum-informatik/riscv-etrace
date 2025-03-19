// Copyright (C) 2024 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

use core::fmt;
use core::fmt::Formatter;

pub mod binary;
pub mod format;

#[cfg(test)]
mod tests;

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
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct Instruction {
    pub size: InstructionSize,
    /// If the instruction was parsed, the name is always available.
    pub kind: Option<Kind>,
}

impl Instruction {
    pub(crate) fn from_binary(bin_instr: &InstructionBits) -> Self {
        match bin_instr {
            InstructionBits::Bit32(num) => Self {
                size: InstructionSize::Normal,
                kind: Kind::decode_32(*num),
            },
            InstructionBits::Bit16(num) => Self {
                size: InstructionSize::Compressed,
                kind: Kind::decode_16(*num),
            },
        }
    }
}

impl From<InstructionBits> for Instruction {
    fn from(bits: InstructionBits) -> Self {
        match bits {
            InstructionBits::Bit32(bits) => Self {
                size: InstructionSize::Normal,
                kind: Kind::decode_32(bits),
            },
            InstructionBits::Bit16(bits) => Self {
                size: InstructionSize::Compressed,
                kind: Kind::decode_16(bits),
            },
        }
    }
}
