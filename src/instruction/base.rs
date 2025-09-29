// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Base instruction set
//!
//! This module provides definitions for representing RISC-V base instruction
//! set variants such as `RV32I` and utilities for decoding instructions.

use super::{format, Kind};

/// RISC-V base instruction set variant
///
/// The RISC-V specification(s) define a small set of base instruction sets,
/// such as `RV32I`, and various extensions (such as `M` or `C`). An encoding
/// of any given instruction does not differ between sets of extensions
/// supported, but it may differ between base instruction sets.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Set {
    Rv32I,
    Rv64I,
}

impl Set {
    /// Decode a 32bit ("normal") instruction
    ///
    /// Returns an instruction [`Kind`] if it can be decoded, that is if that
    /// instruction is known. As only a small part of all RISC-V instruction is
    /// relevant, we don't consider unknown instructions an error.
    #[allow(clippy::unusual_byte_groupings)]
    pub fn decode_32(self, insn: u32) -> Option<Kind> {
        let funct3 = (insn >> 12) & 0x7;

        match OpCode::from(insn) {
            OpCode::MiscMem => match funct3 {
                0b000 => Some(Kind::fence),
                0b001 => Some(Kind::fence_i),
                _ => None,
            },
            OpCode::Lui => Some(Kind::lui(insn.into())),
            OpCode::Auipc => Some(Kind::auipc(insn.into())),
            OpCode::Branch => match funct3 {
                0b000 => Some(Kind::beq(insn.into())),
                0b001 => Some(Kind::bne(insn.into())),
                0b100 => Some(Kind::blt(insn.into())),
                0b101 => Some(Kind::bge(insn.into())),
                0b110 => Some(Kind::bltu(insn.into())),
                0b111 => Some(Kind::bgeu(insn.into())),
                _ => None,
            },
            OpCode::Jalr => Some(Kind::jalr(insn.into())),
            OpCode::Jal => Some(Kind::jal(insn.into())),
            OpCode::System => match insn >> 7 {
                0b000000000000_00000_000_00000 => Some(Kind::ecall),
                0b000000000001_00000_000_00000 => Some(Kind::ebreak),
                0b000100000010_00000_000_00000 => Some(Kind::sret),
                0b001100000010_00000_000_00000 => Some(Kind::mret),
                0b000100000101_00000_000_00000 => Some(Kind::wfi),
                _ if (insn >> 25) == 0b0001001 => Some(Kind::sfence_vma),
                _ => None,
            },
            _ => None,
        }
    }

    /// Decode a 16bit ("compressed") instruction
    ///
    /// Returns an instruction [`Kind`] if it can be decoded, that is if that
    /// instruction is known. As only a small part of all RISC-V instruction is
    /// relevant, we don't consider unknown instructions an error.
    pub fn decode_16(self, insn: u16) -> Option<Kind> {
        let op = insn & 0x3;
        let func3 = insn >> 13;
        match (op, func3) {
            (0b01, 0b001) if self == Self::Rv32I => Some(Kind::c_jal(insn.into())),
            (0b01, 0b011) => {
                let data = format::TypeU::from(insn);
                if data.rd != 0 && data.rd != 2 {
                    Some(Kind::c_lui(data))
                } else {
                    None
                }
            }
            (0x01, 0b101) => Some(Kind::c_j(insn.into())),
            (0x01, 0b110) => Some(Kind::c_beqz(insn.into())),
            (0x01, 0b111) => Some(Kind::c_bnez(insn.into())),
            (0b10, 0b100) => {
                let data = format::TypeR::from(insn);
                let bit12 = (insn >> 12) & 0x1;
                match (bit12, data.rs1, data.rs2) {
                    (0, r, 0) if r != 0 => Some(Kind::c_jr(data)),
                    (1, r, 0) if r != 0 => Some(Kind::c_jalr(data)),
                    (1, 0, 0) => Some(Kind::c_ebreak),
                    _ => None,
                }
            }
            _ => None,
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
        use OpCode::*;

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
