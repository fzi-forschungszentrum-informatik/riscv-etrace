// Copyright (C) 2024, 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Instruction disassembly/decoding and information
//!
//! This module provides utilities for decoding [`Instruction`]s and for
//! extracting information relevant for tracing.

pub mod base;
pub mod binary;
pub mod format;

#[cfg(feature = "elf")]
pub mod elf;

#[cfg(test)]
mod tests;

use core::fmt;

use format::Register;

/// Bits from which [`Instruction`]s can be disassembled
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Bits {
    Bit32(u32),
    Bit16(u16),
}

impl Bits {
    /// Extract [`Bits`] from a raw byte slice
    ///
    /// Try to extract [`Bits`] from the beginning of the given slice, honoring
    /// the Base Instruction-Length Encoding specified in Section 1.5 of The
    /// RISC-V Instruction Set Manual Volume I.
    ///
    /// Returns a tuple containing the [`Bits`] and the remaining part of the
    /// slice if successful. Returns `None` if the beginning does not appear to
    /// be either a 16 or 32 bit instruction, or if the slice does not contain
    /// enough bytes.
    pub fn extract(data: &[u8]) -> Option<(Self, &[u8])> {
        match data {
            [a, b, r @ ..] if a & 0b11 != 0b11 => {
                Some((Self::Bit16(u16::from_le_bytes([*a, *b])), r))
            }
            [a, b, c, d, r @ ..] if a & 0b11100 != 0b11100 => {
                Some((Self::Bit32(u32::from_le_bytes([*a, *b, *c, *d])), r))
            }
            _ => None,
        }
    }

    /// Decode this "raw" instruction to an [`Instruction`]
    ///
    /// Decodes an [`Instruction`], including the instruction [`Kind`] if it is
    /// known.
    pub fn decode(self, base: base::Set) -> Instruction {
        match self {
            Self::Bit32(bits) => Instruction {
                size: Size::Normal,
                kind: base.decode_32(bits),
            },
            Self::Bit16(bits) => Instruction {
                size: Size::Compressed,
                kind: base.decode_16(bits),
            },
        }
    }
}

/// Specific [`Instruction`] kinds relevant for tracing
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

/// Construction
impl Kind {
    /// Create a `beq` instruction
    pub fn new_beq(rs1: Register, rs2: Register, imm: i16) -> Self {
        Self::beq(format::TypeB { rs1, rs2, imm })
    }

    /// Create a `bne` instruction
    pub fn new_bne(rs1: Register, rs2: Register, imm: i16) -> Self {
        Self::bne(format::TypeB { rs1, rs2, imm })
    }

    /// Create a `blt` instruction
    pub fn new_blt(rs1: Register, rs2: Register, imm: i16) -> Self {
        Self::blt(format::TypeB { rs1, rs2, imm })
    }

    /// Create a `bge` instruction
    pub fn new_bge(rs1: Register, rs2: Register, imm: i16) -> Self {
        Self::bge(format::TypeB { rs1, rs2, imm })
    }

    /// Create a `bltu` instruction
    pub fn new_bltu(rs1: Register, rs2: Register, imm: i16) -> Self {
        Self::bltu(format::TypeB { rs1, rs2, imm })
    }

    /// Create a `bgeu` instruction
    pub fn new_bgeu(rs1: Register, rs2: Register, imm: i16) -> Self {
        Self::bgeu(format::TypeB { rs1, rs2, imm })
    }

    /// Create an `auipc` instruction
    pub fn new_auipc(rd: Register, imm: i32) -> Self {
        Self::auipc(format::TypeU { rd, imm })
    }

    /// Create a `lui` instruction
    pub fn new_lui(rd: Register, imm: i32) -> Self {
        Self::lui(format::TypeU { rd, imm })
    }

    /// Create a `c.beqz` instruction
    pub fn new_c_beqz(rs1: Register, imm: i16) -> Self {
        Self::c_beqz(format::TypeB { rs1, rs2: 0, imm })
    }

    /// Create a `c.bnez` instruction
    pub fn new_c_bnez(rs1: Register, imm: i16) -> Self {
        Self::c_bnez(format::TypeB { rs1, rs2: 0, imm })
    }

    /// Create a `jal` instruction
    pub fn new_jal(rd: Register, imm: i32) -> Self {
        Self::jal(format::TypeJ { rd, imm })
    }

    /// Create a `c.j` instruction
    pub fn new_c_j(rd: Register, imm: i16) -> Self {
        Self::c_j(format::TypeJ {
            rd,
            imm: imm.into(),
        })
    }

    /// Create a `c.jal` instruction
    pub fn new_c_jal(rd: Register, imm: i16) -> Self {
        Self::c_jal(format::TypeJ {
            rd,
            imm: imm.into(),
        })
    }

    /// Create a `c.lui` instruction
    pub fn new_c_lui(rd: Register, imm: i32) -> Self {
        Self::c_lui(format::TypeU { rd, imm })
    }

    /// Create a `c.jr` instruction
    pub fn new_c_jr(rd: Register) -> Self {
        Self::c_jr(format::TypeR {
            rd,
            rs1: rd,
            rs2: 0,
        })
    }

    /// Create a `c.jalr` instruction
    pub fn new_c_jalr(rd: Register) -> Self {
        Self::c_jalr(format::TypeR {
            rd,
            rs1: rd,
            rs2: 0,
        })
    }

    /// Create a `jalr` instruction
    pub fn new_jalr(rd: Register, rs1: Register, imm: i16) -> Self {
        Self::jalr(format::TypeI { rd, rs1, imm })
    }
}

/// Queries
impl Kind {
    /// Determine the branch target
    ///
    /// If [`Self`] refers to a branch instruction, this fn returns the
    /// immediate, which is the branch target relative to this instruction.
    /// Returns `None` if [`Self`] does not refer to a (known) branch
    /// instruction. Jump instructions are not considered branch instructions.
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
    /// If [`Self`] refers to a jump instruction that in itself determines the
    /// jump target, this fn returns that target relative to this instruction.
    /// Returns `None` if [`Self`] does not refer to a (known) jump instruction
    /// or if the branch target cannot be inferred based on the instruction
    /// alone.
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
    /// If [`Self`] refers to a jump instruction that in itself does not
    /// determine the (relative) jump target, this fn returns the information
    /// neccessary to determine the target in the form of a register number
    /// (first tuple element) and an offset (second tuple element). The jump
    /// target is computed by adding the offset to the contents of the denoted
    /// register.
    ///
    /// Note that a `jalr` instruciton's target will always be considered
    /// uninferable unless the source register is the `zero` register, even if
    /// it is preceeded directly by `auipc` and `addi` instructions defining a
    /// constant jump target. However, callers may be able to infer the jump
    /// target in such situations using statically determined register values.
    ///
    /// Branch instructions are not considered jump instructions.
    pub fn uninferable_jump(self) -> Option<(Register, i16)> {
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
    /// Returns `true` if [`Self`] refers to one of the (known) special
    /// instructions that return from a trap.
    pub fn is_return_from_trap(self) -> bool {
        matches!(self, Self::uret | Self::sret | Self::mret | Self::dret)
    }

    /// Determine whether this instruction causes an uninferable discontinuity
    ///
    /// Returns `true` if [`Self`] refers to an instruction that causes a (PC)
    /// discontinuity with a target that can not be inferred from the
    /// instruction alone. This is the case if the instruction is either
    /// * an [uninferable jump][Self::uninferable_jump],
    /// * a [return from trap][Self::is_return_from_trap] or
    /// * an `ecall` or `ebreak` (compressed or uncompressed).
    pub fn is_uninferable_discon(self) -> bool {
        self.uninferable_jump().is_some() || self.is_return_from_trap() || self.is_ecall_or_ebreak()
    }

    /// Determine whether this instruction is an `ecall` or `ebreak`
    ///
    /// Returns `true` if this refers to either an `ecall`, `ebreak` or
    /// `c.ebreak`.
    pub fn is_ecall_or_ebreak(self) -> bool {
        matches!(self, Self::ecall | Self::ebreak | Self::c_ebreak)
    }

    /// Determine whether this instruction can be considered a function call
    ///
    /// Returns `true` if [`Self`] refers to an instruction that we consider a
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
    /// Returns `true` if [`Self`] refers to an instruction that we consider a
    /// function return, that is a jump register instruction with `ra` (the
    /// return address register) as `rs1`.
    pub fn is_return(self) -> bool {
        matches!(
            self,
            Self::jalr(format::TypeI { rd: 0, rs1: 1, .. })
                | Self::c_jr(format::TypeR { rs1: 1, .. })
        )
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            // TypeR
            Self::c_jr(d) => write!(f, "c.jr x{}", d.rs1),
            Self::c_jalr(d) => write!(f, "c.jalr x{}", d.rs1),

            // TypeJ
            Self::c_jal(d) => write!(f, "c.jal 0x{:X}", d.imm),
            Self::c_j(d) => write!(f, "c.j 0x{:X}", d.imm),

            // No change
            Self::jal(d) => write!(f, "jal {}", d),

            // TypeU
            Self::c_lui(d) => write!(f, "c.lui {}", d),
            Self::auipc(d) => write!(f, "auipc {}", d),
            Self::lui(d) => write!(f, "lui {}", d),

            // TypeI
            Self::jalr(d) => write!(f, "jalr {}", d),

            // TypeB
            Self::c_beqz(d) => write!(f, "c.beqz x{}, 0x{:X}", d.rs1, d.imm),
            Self::c_bnez(d) => write!(f, "c.bnez x{}, 0x{:X}", d.rs1, d.imm),
            Self::beq(d) => write!(f, "beq {}", d),
            Self::bne(d) => write!(f, "bne {}", d),
            Self::blt(d) => write!(f, "blt {}", d),
            Self::bge(d) => write!(f, "bge {}", d),
            Self::bltu(d) => write!(f, "bltu {}", d),
            Self::bgeu(d) => write!(f, "bgeu {}", d),

            // No type implemented instructions
            Self::c_ebreak => write!(f, "c.ebreak"),
            Self::ebreak => write!(f, "ebreak"),
            Self::fence_i => write!(f, "fence.i"),
            Self::ecall => write!(f, "ecall"),
            Self::wfi => write!(f, "wfi"),
            Self::sfence_vma => write!(f, "sfence.vma"),
            Self::fence => write!(f, "fence"),
            Self::mret => write!(f, "mret"),
            Self::sret => write!(f, "sret"),
            Self::uret => write!(f, "uret"),
            Self::dret => write!(f, "dret"),
        }
    }
}

/// Length of single RISC-V [`Instruction`]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Size {
    Compressed = 2,
    Normal = 4,
}

impl Default for Size {
    fn default() -> Self {
        Self::Normal
    }
}

impl From<Size> for u64 {
    fn from(size: Size) -> Self {
        size as u64
    }
}

/// A single RISC-V instruction
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct Instruction {
    /// [`Size`] of the instruction
    pub size: Size,
    /// [`Kind`] of the instruciton if known
    pub kind: Option<Kind>,
}

impl Instruction {
    /// Extract an instruction from a raw byte slice
    ///
    /// Try to extract [`Bits`] from the beginning of the given slice, then
    /// decode them into an [`Instruction`]. See [`Bits::extract`] and
    /// [`Bits::decode`] for details.
    pub fn extract(data: &[u8], base: base::Set) -> Option<(Self, &[u8])> {
        Bits::extract(data).map(|(b, r)| (b.decode(base), r))
    }
}

impl From<Kind> for Instruction {
    fn from(kind: Kind) -> Self {
        let size = match kind {
            Kind::mret | Kind::sret | Kind::uret | Kind::dret => Size::Normal,
            Kind::fence | Kind::sfence_vma | Kind::wfi => Size::Normal,
            Kind::ecall | Kind::ebreak | Kind::fence_i => Size::Normal,
            Kind::beq(_) | Kind::bne(_) | Kind::blt(_) | Kind::bge(_) => Size::Normal,
            Kind::bltu(_) | Kind::bgeu(_) => Size::Normal,
            Kind::auipc(_) | Kind::lui(_) => Size::Normal,
            Kind::c_beqz(_) | Kind::c_bnez(_) => Size::Compressed,
            Kind::jal(_) | Kind::jalr(_) => Size::Normal,
            Kind::c_j(_) | Kind::c_jal(_) | Kind::c_jr(_) | Kind::c_jalr(_) => Size::Compressed,
            Kind::c_lui(_) => Size::Compressed,
            Kind::c_ebreak => Size::Compressed,
        };
        Self {
            kind: Some(kind),
            size,
        }
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            Some(kind) => write!(f, "{}", kind),
            None => write!(f, ""),
        }
    }
}

/// An unknown 16bit [`Instruction`]
pub const COMPRESSED: Instruction = Instruction {
    kind: None,
    size: Size::Compressed,
};

/// An unknown 32bit [`Instruction`]
pub const UNCOMPRESSED: Instruction = Instruction {
    kind: None,
    size: Size::Normal,
};
