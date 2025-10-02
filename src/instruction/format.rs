// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Variable instruction fields
//!
//! This module provides data types holding variable fields of instruction
//! encoding variants as defined by The RISC-V Instruction Set Manual Volume I
//! [^spec] sections 2.2 Base Instruction Formats and 2.3 Immediate Encoding
//! Variants. The variants, or "types" differ in their variable fields, that is
//! what register and immediate fields are present and in the case of immediates
//! also in their position and composition.
//!
//! This module defines a data type for each of those variants with a [`From`]
//! impl that extracts those fields from an instruction represented as an
//! [`u32`]. In addition, some types also impl `From<u16>`, extracting the
//! information from compressed instructions as defined in section 26.2
//! Compressed Instruction Formats of the aforementioned The RISC-V Instruction
//! Set Manual Volume I.
//!
//! The extracted values reflect the fields' semantics: for immediates, we
//! extract the immediate value rather than the bit-patters as present in the
//! encoded instruction. We thus differentiate between S- and B-type
//! instrucitons as well as between U- and J-type instructions.
//!
//! [^spec]: found here: <https://riscv.org/specifications/ratified/>

/// Variable fields in R-type and CR-type instructions
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TypeR {
    /// Destination register
    pub rd: Register,
    /// Source register 1
    pub rs1: Register,
    /// Source register 2
    pub rs2: Register,
}

impl From<u32> for TypeR {
    fn from(insn: u32) -> Self {
        Self {
            rd: rd_from(insn),
            rs1: rs1_from(insn),
            rs2: rs2_from(insn),
        }
    }
}

impl From<u16> for TypeR {
    fn from(insn: u16) -> Self {
        let rd = rd_from(insn.into());
        Self {
            rd,
            rs1: rd,
            rs2: rs2_from_compressed(insn),
        }
    }
}

/// Variable fields in I-type instructions
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TypeI {
    /// Destination register
    pub rd: Register,
    /// Source register 1
    pub rs1: Register,
    /// Immediate
    ///
    /// The immediate is sign-extended from the 12bit-wide field in encoded
    /// 32bit instruction. It is thus in the range `-2048..=2047`.
    pub imm: i16,
}

impl From<u32> for TypeI {
    fn from(insn: u32) -> Self {
        let imm = sign_extend_u16((insn >> 20) as u16, 11);

        Self {
            rd: rd_from(insn),
            rs1: rs1_from(insn),
            imm,
        }
    }
}

/// Variable fields in S-type instructions
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TypeS {
    /// Source register 1
    pub rs1: Register,
    /// Source register 2
    pub rs2: Register,
    /// Immediate
    ///
    /// The immediate is assembled from the fields in encoded 32bit
    /// instructions, which are 12bit in total, and then sign-extended. It is
    /// thus in the range `-2048..=2047`.
    pub imm: i16,
}

impl From<u32> for TypeS {
    fn from(insn: u32) -> Self {
        let imm = ((insn >> 7) & 0x01f) | ((insn >> (25 - 5)) & 0xfe0);

        Self {
            rs1: rs1_from(insn),
            rs2: rs2_from(insn),
            imm: sign_extend_u16(imm as u16, 11),
        }
    }
}

/// Variable fields in B-type and CB-type instructions
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TypeB {
    /// Source register 1
    pub rs1: Register,
    /// Source register 2
    pub rs2: Register,
    /// Immediate
    ///
    /// The immediate is assembled from the fields in the encoded 32bit
    /// instruction, which are 12bit in total, and then sign-extended. Since the
    /// lowest bit is not encoded in the instruction but defined as `0`, the
    /// value is a multiple of two in the range `-4096..=4094`.
    ///
    /// For 16bit instrucitons, the range is `-256..=254`.
    pub imm: i16,
}

impl From<u32> for TypeB {
    fn from(insn: u32) -> Self {
        let imm = ((insn >> 7) & 0x001e)
            | ((insn >> (25 - 5)) & 0x07e0)
            | ((insn << (11 - 7)) & 0x0800)
            | ((insn >> (31 - 12)) & 0x1000);
        Self {
            rs1: rs1_from(insn),
            rs2: rs2_from(insn),
            imm: sign_extend_u16(imm as u16, 12),
        }
    }
}

impl From<u16> for TypeB {
    fn from(insn: u16) -> Self {
        let imm = ((insn >> (3 - 1)) & 0x006)
            | ((insn >> (10 - 3)) & 0x018)
            | ((insn << (5 - 2)) & 0x020)
            | ((insn << (7 - 6)) & 0x0c0)
            | ((insn >> (12 - 8)) & 0x100);
        Self {
            rs1: rs1c_from(insn),
            rs2: 0,
            imm: sign_extend_u16(imm, 8),
        }
    }
}

/// Variable fields in U-type instructions
///
/// This type also allows extracting the destination register and immediate from
/// `c.lui` instructions.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TypeU {
    /// Destination register
    pub rd: Register,
    /// Immediate
    ///
    /// The immediate is extracted from the upper 20 bits of 32bit instructions,
    /// as the upper 20 bits of the immediate. Thus, the lower 12 bits are
    /// always zero.
    ///
    /// For 16bit instructions, the lower bits are also zero, but the overall
    /// value is sign-extended from the 5 bits of the immediate. The range is
    /// thus `-65536..=61440`.
    pub imm: i32,
}

impl From<u32> for TypeU {
    fn from(insn: u32) -> Self {
        Self {
            rd: rd_from(insn),
            imm: (insn & 0xfffff000) as i32,
        }
    }
}

impl From<u16> for TypeU {
    fn from(insn: u16) -> Self {
        let insn: u32 = insn.into();
        let imm = ((insn << (12 - 2)) & 0x0001f000) | ((insn << (17 - 12)) & 0x00020000);
        Self {
            rd: rd_from(insn),
            imm: sign_extend_u32(imm, 17),
        }
    }
}

/// Variable fields in J-type instructions
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TypeJ {
    /// Destination register
    pub rd: Register,
    /// Immediate
    ///
    /// The immediate is assembled from the fields in encoded 32bit
    /// instructions, which are 20bit in total, and then sign-extended. Since
    /// the lowest bit is not encoded in the instruction but defined as `0`, the
    /// value is a multiple of two in the range `-1048576..=1048574`.
    ///
    /// For 16bit instructions, the range is `-2048..=2046`.
    pub imm: i32,
}

impl From<u32> for TypeJ {
    fn from(insn: u32) -> Self {
        let imm = ((insn >> (21 - 1)) & 0x0007fe)
            | ((insn >> (20 - 11)) & 0x000800)
            | (insn & 0x0ff000)
            | ((insn >> (31 - 20)) & 0x100000);
        Self {
            rd: rd_from(insn),
            imm: sign_extend_u32(imm, 20),
        }
    }
}

impl From<u16> for TypeJ {
    fn from(insn: u16) -> Self {
        let imm = ((insn >> (3 - 1)) & 0x00e)
            | ((insn >> (11 - 4)) & 0x010)
            | ((insn << (5 - 2)) & 0x020)
            | ((insn >> (7 - 6)) & 0x040)
            | ((insn << (7 - 6)) & 0x080)
            | ((insn >> (9 - 8)) & 0x300)
            | ((insn << (10 - 8)) & 0x400)
            | ((insn >> (12 - 11)) & 0x800);
        Self {
            rd: 0,
            imm: sign_extend_u32(imm as u32, 11),
        }
    }
}

/// Register number
pub type Register = u8;

/// Extract the destination register form a 32bit instruction
const fn rd_from(insn: u32) -> u8 {
    (insn >> 7) as u8 & REG_MASK
}

/// Extract source register 1 form a 32bit instruction
const fn rs1_from(insn: u32) -> u8 {
    (insn >> 15) as u8 & REG_MASK
}

/// Extract source register 2 form a 32bit instruction
const fn rs2_from(insn: u32) -> u8 {
    (insn >> 20) as u8 & REG_MASK
}

/// Extract (regular) source register 2 form a 16bit instruction
const fn rs2_from_compressed(insn: u16) -> u8 {
    (insn >> 2) as u8 & REG_MASK
}

/// Extract a compressed source register 1 form a 16bit instruction
const fn rs1c_from(insn: u16) -> u8 {
    ((insn >> 7) as u8 & 0x07) | 0x08
}

/// Convert an [`u16`] to an [`i16`], sign extending it from a given bit
const fn sign_extend_u16(value: u16, pos: u8) -> i16 {
    if (value & (1 << pos)) > 0 {
        (value | !((1 << pos) - 1)) as i16
    } else {
        value as i16
    }
}

/// Convert an [`u32`] to an [`i32`], sign extending it from a given bit
const fn sign_extend_u32(value: u32, pos: u8) -> i32 {
    if (value & (1 << pos)) > 0 {
        (value | !((1 << pos) - 1)) as i32
    } else {
        value as i32
    }
}

const REG_MASK: u8 = 0x1f;
