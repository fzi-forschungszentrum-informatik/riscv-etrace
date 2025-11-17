// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Utility for truncating fields of a specific bit-width

/// Truncate a value to a given bit-width
pub trait TruncateNum {
    /// Truncate a value to the given width `bit_count`
    ///
    /// For unsigned values, all upper bits will be zeroed. signed values will
    /// be sign-extended, preserving only the lower `bit_count` bits from the
    /// original value.
    fn truncated(self, bit_count: u8) -> Self;
}

impl TruncateNum for u8 {
    fn truncated(self, bit_count: u8) -> Self {
        self & !((!0u8).checked_shl(bit_count.into()).unwrap_or(0))
    }
}

impl TruncateNum for u16 {
    fn truncated(self, bit_count: u8) -> Self {
        self & !((!0u16).checked_shl(bit_count.into()).unwrap_or(0))
    }
}

impl TruncateNum for u32 {
    fn truncated(self, bit_count: u8) -> Self {
        self & !((!0u32).checked_shl(bit_count.into()).unwrap_or(0))
    }
}

impl TruncateNum for u64 {
    fn truncated(self, bit_count: u8) -> Self {
        self & !((!0u64).checked_shl(bit_count.into()).unwrap_or(0))
    }
}

impl TruncateNum for usize {
    fn truncated(self, bit_count: u8) -> Self {
        self & !((!0usize).checked_shl(bit_count.into()).unwrap_or(0))
    }
}

impl TruncateNum for i64 {
    fn truncated(self, bit_count: u8) -> Self {
        let Some(ref_bit) = bit_count.checked_sub(1) else {
            return 0;
        };

        let upper_bits = (!0i64).checked_shl(bit_count.into()).unwrap_or(0);
        if self & (1 << ref_bit) == 0 {
            self & !upper_bits
        } else {
            self | upper_bits
        }
    }
}
