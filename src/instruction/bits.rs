// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Utilities for dissecting a bunch of bytes into [`Instruction`] [`Bits`]

use super::{base, Instruction, Size};

/// Bits from which [`Instruction`]s can be disassembled
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Bits {
    Bit16(u16),
    Bit32(u32),
    Bit48(u64),
    Bit64(u64),
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
            [a, b, c, d, e, f, r @ ..] if a & 0x3f == 0x1f => Some((
                Self::Bit48(u64::from_le_bytes([*a, *b, *c, *d, *e, *f, 0, 0])),
                r,
            )),
            [a, b, c, d, e, f, g, h, r @ ..] if a & 0x7f == 0x3f => Some((
                Self::Bit64(u64::from_le_bytes([*a, *b, *c, *d, *e, *f, *g, *h])),
                r,
            )),
            _ => None,
        }
    }

    /// Decode this "raw" instruction to an [`Instruction`]
    ///
    /// Decodes an [`Instruction`], including the instruction
    /// [`Kind`][super::Kind] if it is known.
    pub fn decode(self, base: base::Set) -> Instruction {
        match self {
            Self::Bit16(bits) => Instruction {
                size: Size::Compressed,
                kind: base.decode_16(bits),
            },
            Self::Bit32(bits) => Instruction {
                size: Size::Normal,
                kind: base.decode_32(bits),
            },
            Self::Bit48(bits) => Instruction {
                size: Size::Wide,
                kind: base.decode_48(bits),
            },
            Self::Bit64(bits) => Instruction {
                size: Size::ExtraWide,
                kind: base.decode_64(bits),
            },
        }
    }
}
