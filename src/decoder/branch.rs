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
