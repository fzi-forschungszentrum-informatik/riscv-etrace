// Copyright (C) 2024, 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Instruction disassembly/decoding and information
//!
//! This module provides utilities for decoding [`Instruction`]s and for
//! extracting [information][info] relevant for tracing. Aside from the [`Size`]
//! within the binary, an [`Instruction`] carries an [`Info`] which provides any
//! information necessary for reconstructing discontinuities.
//!
//! The [`Info`] trait is implemented for [`Kind`], a representation of only
//! instructions relevant for control flow reconstruction. In addition, it is
//! (optionally) implemented for external types that may provide more
//! information (e.g. [`riscv_isa::Instruction`]).
//!
//! # Instruction decode
//!
//! [`Instruction`]s are usually decoded by first extracting the [`Bits`]
//! associated to an [`Instruction`] based on RISC-V's instruction length
//! encoding and then decoding the [`Info`] using an [`info::Decode`] capturing
//! decoding parameters such as [`base::Set`].

pub mod base;
pub mod bits;
pub mod format;
pub mod info;

#[cfg(test)]
mod tests;

use core::fmt;

use bits::Bits;
use format::Register;
use info::Info;

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

impl Info for Kind {
    type Register = Register;

    fn branch_target(&self) -> Option<i16> {
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

    fn inferable_jump_target(&self) -> Option<i32> {
        match self {
            Self::jal(d) => Some(d.imm),
            Self::c_jal(d) => Some(d.imm),
            Self::c_j(d) => Some(d.imm),
            Self::jalr(format::TypeI { rs1: 0, imm, .. }) => Some((*imm).into()),
            _ => None,
        }
    }

    fn uninferable_jump_target(&self) -> Option<(Self::Register, i16)> {
        match self {
            Self::c_jalr(d) => Some((d.rs1, 0)),
            Self::c_jr(d) => Some((d.rs1, 0)),
            Self::jalr(d) => Some((d.rs1, d.imm)),
            _ => None,
        }
        .filter(|(r, _)| *r != 0)
    }

    fn upper_immediate(&self, pc: u64) -> Option<(Self::Register, u64)> {
        match self {
            Self::auipc(d) => Some((d.rd, pc.wrapping_add_signed(d.imm.into()))),
            Self::lui(d) => Some((d.rd, d.imm as u64)),
            Self::c_lui(d) => Some((d.rd, d.imm as u64)),
            _ => None,
        }
    }

    fn is_return_from_trap(&self) -> bool {
        matches!(self, Self::uret | Self::sret | Self::mret | Self::dret)
    }

    fn is_ecall_or_ebreak(&self) -> bool {
        matches!(self, Self::ecall | Self::ebreak | Self::c_ebreak)
    }

    fn is_call(&self) -> bool {
        match self {
            Self::jalr(format::TypeI { rd: 1, rs1, .. }) => *rs1 != 5,
            Self::jalr(format::TypeI { rd: 5, rs1, .. }) => *rs1 != 1,
            Self::c_jalr(format::TypeR { rs1, .. }) => *rs1 != 5,
            Self::jal(format::TypeJ { rd, .. }) => *rd == 1 || *rd == 5,
            Self::c_jal(_) => true,
            _ => false,
        }
    }

    fn is_return(&self) -> bool {
        match self {
            Self::jalr(format::TypeI { rd, rs1: 1, .. }) => *rd != 1 && *rd != 5,
            Self::jalr(format::TypeI { rd, rs1: 5, .. }) => *rd != 1 && *rd != 5,
            Self::c_jr(format::TypeR { rs1, .. }) => *rs1 == 1 || *rs1 == 5,
            _ => false,
        }
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
            Self::jal(d) => write!(f, "jal {d}"),

            // TypeU
            Self::c_lui(d) => write!(f, "c.lui {d}"),
            Self::auipc(d) => write!(f, "auipc {d}"),
            Self::lui(d) => write!(f, "lui {d}"),

            // TypeI
            Self::jalr(d) => write!(f, "jalr {d}"),

            // TypeB
            Self::c_beqz(d) => write!(f, "c.beqz x{}, 0x{:X}", d.rs1, d.imm),
            Self::c_bnez(d) => write!(f, "c.bnez x{}, 0x{:X}", d.rs1, d.imm),
            Self::beq(d) => write!(f, "beq {d}"),
            Self::bne(d) => write!(f, "bne {d}"),
            Self::blt(d) => write!(f, "blt {d}"),
            Self::bge(d) => write!(f, "bge {d}"),
            Self::bltu(d) => write!(f, "bltu {d}"),
            Self::bgeu(d) => write!(f, "bgeu {d}"),

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

/// Length of a single RISC-V [`Instruction`]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Size {
    Compressed = 2,
    Normal = 4,
    Wide = 6,
    ExtraWide = 8,
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
pub struct Instruction<I: Info = Option<Kind>> {
    /// [`Size`] of the instruction
    pub size: Size,
    /// [`Info`] associated to this instruction
    pub info: I,
}

impl<I: Info> Instruction<I> {
    /// Extract an instruction from a raw byte slice
    ///
    /// Try to extract [`Bits`] from the beginning of the given slice, then
    /// decode them into an [`Instruction`]. See [`Bits::extract`] and
    /// [`info::Decode`] for details.
    pub fn extract<'d, D: info::Decode<I>>(data: &'d [u8], base: &D) -> Option<(Self, &'d [u8])> {
        Bits::extract(data).map(|(b, r)| (Self::decode(b, base), r))
    }

    /// Decode an instruction from the given [`Bits`]
    ///
    /// Decode the given [`Bits`] into an [`Instruction`] using the given
    /// [`info::Decode`].
    pub fn decode<D: info::Decode<I>>(bits: Bits, base: &D) -> Self {
        let size = bits.size();
        let info = base.decode_bits(bits);
        Self { size, info }
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
            info: Some(kind),
            size,
        }
    }
}

impl<I: Info> Info for Instruction<I> {
    type Register = I::Register;

    fn branch_target(&self) -> Option<i16> {
        self.info.branch_target()
    }

    fn inferable_jump_target(&self) -> Option<i32> {
        self.info.inferable_jump_target()
    }

    fn uninferable_jump_target(&self) -> Option<(Self::Register, i16)> {
        self.info.uninferable_jump_target()
    }

    fn upper_immediate(&self, pc: u64) -> Option<(Self::Register, u64)> {
        self.info.upper_immediate(pc)
    }

    fn is_return_from_trap(&self) -> bool {
        self.info.is_return_from_trap()
    }

    fn is_ecall_or_ebreak(&self) -> bool {
        self.info.is_ecall_or_ebreak()
    }

    fn is_call(&self) -> bool {
        self.info.is_call()
    }

    fn is_return(&self) -> bool {
        self.info.is_return()
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.info {
            Some(kind) => fmt::Display::fmt(kind, f),
            None => Ok(()),
        }
    }
}

/// An unknown 16bit [`Instruction`]
pub const COMPRESSED: Instruction = Instruction {
    info: None,
    size: Size::Compressed,
};

/// An unknown 32bit [`Instruction`]
pub const UNCOMPRESSED: Instruction = Instruction {
    info: None,
    size: Size::Normal,
};
