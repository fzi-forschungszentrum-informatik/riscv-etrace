// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Branch map utilities

use super::{Decode, Decoder, Error};

/// A record of branches that are taken or not taken
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct Map {
    count: u8,
    map: u64,
}

impl Map {
    /// Remove the oldest branch information and return it
    pub fn pop_taken(&mut self) -> Option<bool> {
        let count = self.count.checked_sub(1)?;
        let res = self.map & 1 == 0;

        self.map >>= 1;
        self.count = count;

        Some(res)
    }

    /// Push a new branch information
    pub fn push_branch_taken(&mut self, taken: bool) {
        let count = self.count;
        let bit = 1u64.checked_shl(count.into()).unwrap_or_default();
        self.map = if taken {
            self.map & !bit
        } else {
            self.map | bit
        };

        self.count = count.saturating_add(1);
    }

    /// Append another branch map to this one
    ///
    /// The branches from the other map are considered newer than the existing
    /// ones.
    pub fn append(&mut self, other: Self) {
        let count = self.count;
        self.map |= other.map.checked_shl(count.into()).unwrap_or_default();
        self.count = count.saturating_add(other.count);
    }

    /// Retrieve the number of branchs in the map
    pub fn count(&self) -> u8 {
        self.count
    }

    /// Retrieve the raw contents of the map
    ///
    /// The lowest valued bit corresponds to the oldest branch. Set bits
    /// represent branches not taken, unset bits represent taken branches.
    pub fn raw_map(&self) -> u64 {
        self.map
    }
}

#[derive(Copy, Clone, Debug)]
pub(super) struct Count(pub u8);

impl Count {
    /// Determine whether this count is zero
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Read a branch map with this count
    pub fn read_branch_map(self, decoder: &mut Decoder) -> Result<Map, Error> {
        let length = core::iter::successors(Some(31), |l| (*l > 0).then_some(l >> 1))
            .take_while(|l| *l >= self.0)
            .last()
            .expect("Could not determine length");
        let mut map = decoder.read_bits(length)?;
        map &= !0u64.checked_shl(self.0.into()).unwrap_or_default();
        Ok(Map { count: self.0, map })
    }

    /// Count for a full branch map
    pub const FULL: Self = Self(31);
}

impl Decode for Count {
    fn decode(decoder: &mut Decoder) -> Result<Self, Error> {
        decoder.read_bits(5).map(Self)
    }
}
