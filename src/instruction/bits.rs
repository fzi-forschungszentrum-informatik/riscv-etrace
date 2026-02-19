// Copyright (C) 2025, 2026 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Utilities for dissecting a bunch of bytes into instruction [`Bits`]

use core::fmt;

use super::Size;

/// Bits from which [`Instruction`][super::Instruction]s can be disassembled
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

    /// Retrieve this instruction's [`Size`]
    pub fn size(self) -> Size {
        match self {
            Self::Bit16(_) => Size::Compressed,
            Self::Bit32(_) => Size::Normal,
            Self::Bit48(_) => Size::Wide,
            Self::Bit64(_) => Size::ExtraWide,
        }
    }
}

impl Default for Bits {
    fn default() -> Self {
        Self::Bit32(0)
    }
}

impl TryFrom<u16> for Bits {
    type Error = u16;

    fn try_from(num: u16) -> Result<Self, Self::Error> {
        if num & 0b11 != 0b11 {
            Ok(Self::Bit16(num))
        } else {
            Err(num)
        }
    }
}

impl TryFrom<u32> for Bits {
    type Error = u32;

    fn try_from(num: u32) -> Result<Self, Self::Error> {
        if num & 0b11 != 0b11 {
            num.try_into().map(Self::Bit16).map_err(|_| num)
        } else if num & 0b11100 != 0b11100 {
            Ok(Self::Bit32(num))
        } else {
            Err(num)
        }
    }
}

impl TryFrom<u64> for Bits {
    type Error = u64;

    fn try_from(num: u64) -> Result<Self, Self::Error> {
        if num & 0x3f == 0x1f && num >> 48 == 0 {
            Ok(Self::Bit48(num))
        } else if num & 0x7f == 0x3f {
            Ok(Self::Bit64(num))
        } else {
            num.try_into()
                .map_err(|_| num)
                .and_then(|n: u32| n.try_into().map_err(Into::into))
        }
    }
}

impl fmt::Display for Bits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bit16(v) => write!(f, "{v:04x}"),
            Self::Bit32(v) => write!(f, "{v:08x}"),
            Self::Bit48(v) => write!(f, "{v:012x}"),
            Self::Bit64(v) => write!(f, "{v:016x}"),
        }
    }
}
