// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Branch map utilities

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
