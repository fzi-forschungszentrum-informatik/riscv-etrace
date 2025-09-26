// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Branch map utilities

use core::fmt;

/// A record of branches that are taken or not taken
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct Map {
    count: u8,
    map: u64,
}

impl Map {
    /// Maximum number of branches a branch map can hold.
    pub const MAX_BRANCHES: u32 = u64::BITS;

    /// Create a new branch map
    ///
    /// # Note
    ///
    /// Panics if `count` is greater than [`MAX_BRANCHES`][Self::MAX_BRANCHES].
    pub(crate) fn new(count: u8, map: u64) -> Self {
        assert!(
            u32::from(count) < Self::MAX_BRANCHES,
            "Attempt to create a branch map with {count} branches",
        );
        Self { count, map }
    }

    /// Remove the oldest branch information and return it
    pub fn pop_taken(&mut self) -> Option<bool> {
        let count = self.count.checked_sub(1)?;
        let res = self.map & 1 == 0;

        self.map >>= 1;
        self.count = count;

        Some(res)
    }

    /// Push a new branch information
    pub fn push_branch_taken(&mut self, taken: bool) -> Result<(), Error> {
        let bit = 1u64
            .checked_shl(self.count.into())
            .ok_or(Error::TooManyBranches)?;
        self.map = if taken {
            self.map & !bit
        } else {
            self.map | bit
        };

        self.count += 1;
        Ok(())
    }

    /// Append another branch map to this one
    ///
    /// The branches from the other map are considered newer than the existing
    /// ones.
    pub fn append(&mut self, other: Self) -> Result<(), Error> {
        let total = self
            .count
            .checked_add(other.count)
            .filter(|c| u32::from(*c) <= Self::MAX_BRANCHES)
            .ok_or(Error::TooManyBranches)?;
        self.map |= other.map << u32::from(self.count);
        self.count = total;
        Ok(())
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

/// Errors produced by [`Map`]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Too many branches
    ///
    /// The operation could not be preformed because the result would exceed the
    /// maximum number of branches a branch map may hold.
    TooManyBranches,
}

impl core::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::TooManyBranches => write!(f, "Too many branches"),
        }
    }
}
