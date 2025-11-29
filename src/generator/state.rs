// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Tracing payload relative state

use crate::config::AddressMode;
use crate::types::{branch, Context};

use super::error::Error;

/// State in relation to some previously issued tracing payload
///
/// This type captures some aspects of the current execution state relative to
/// some previous cycle, with the exception of it representing the first (known)
/// state.
#[derive(Default, Clone, Debug)]
pub struct State {
    branches: branch::Map,
    last_address: Option<u64>,
    address_mode: AddressMode,
}

impl State {
    /// Create a new state
    pub fn new(address_mode: AddressMode) -> Self {
        Self {
            address_mode,
            ..Default::default()
        }
    }

    /// Add a branch to the branch map
    pub fn add_branch(&mut self, branch_taken: bool) -> Result<(), Error> {
        self.branches
            .push_branch_taken(branch_taken)
            .map_err(Error::CannotAddBranches)
    }

    /// Retrieve the number of branches in the branch map
    pub fn branches(&self) -> u8 {
        self.branches.count()
    }

    /// Set the [`AddressMode`] for address payloads generated from this state
    pub fn set_address_mode(&mut self, mode: AddressMode) {
        self.address_mode = mode;
    }

    /// Reset this state
    pub fn reset(&mut self) {
        self.branches = Default::default();
        self.last_address = None;
    }
}
