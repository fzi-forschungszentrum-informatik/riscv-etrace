// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Tracing payload relative state

use crate::config::AddressMode;
use crate::packet::{payload, sync};
use crate::types::{Context, branch, trap};

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

    /// Create a [`PayloadBuilder`] for creating a payload based on this state
    pub fn payload_builder(
        &mut self,
        address: u64,
        context: Context,
        timestamp: Option<u64>,
    ) -> PayloadBuilder<'_> {
        PayloadBuilder {
            state: self,
            address,
            context,
            timestamp,
            is_branch: false,
        }
    }
}

/// Builder for instruction trace payloads
///
/// This builder allows issuing paylods based on a recorded [`State`]. The
/// issuing process will advance the state, i.e. update the branch map and
/// recorded address as is appropriate for the payload generated.
#[derive(Debug)]
pub struct PayloadBuilder<'s> {
    state: &'s mut State,
    address: u64,
    context: Context,
    timestamp: Option<u64>,
    is_branch: bool,
}

/// State mutation and queries
impl PayloadBuilder<'_> {
    /// Add a branch being taken or not taken from the current address
    pub fn add_branch(&mut self, branch_taken: bool) -> Result<(), Error> {
        self.state.add_branch(branch_taken)?;
        self.is_branch = true;
        Ok(())
    }

    /// Retrieve the number of branches recorded in the state
    pub fn branches(&self) -> u8 {
        self.state.branches()
    }
}

/// Payload issuing
impl PayloadBuilder<'_> {
    /// Issue a [`sync::Start`] payload
    pub fn report_sync(mut self) -> sync::Start {
        let branch = self.sync_branch_flag();
        self.state.last_address = Some(self.address);
        sync::Start {
            branch,
            ctx: self.context(),
            address: self.address,
        }
    }

    /// Issue a [`sync::Trap`] payload
    pub fn report_trap(mut self, thaddr: bool, info: trap::Info) -> sync::Trap {
        let branch = self.sync_branch_flag();
        self.state.last_address = Some(self.address);
        sync::Trap {
            branch,
            ctx: self.context(),
            thaddr,
            address: self.address,
            info,
        }
    }

    /// Retrieve the current [`Context`] as a [`sync::Context`] payload
    pub fn context(&self) -> sync::Context {
        sync::Context {
            privilege: self.context.privilege,
            time: self.timestamp,
            context: self.context.context,
        }
    }

    /// Issue a payload reporting the current address
    pub fn report_address<I, D>(
        self,
        reason: Reason,
    ) -> Result<payload::InstructionTrace<I, D>, Error> {
        let offset = match self.state.address_mode {
            AddressMode::Full => 0,
            AddressMode::Delta => self.state.last_address.ok_or(Error::NoAddressReported)?,
        };
        self.state.last_address = Some(self.address);

        let address = 0i64
            .wrapping_add_unsigned(self.address)
            .wrapping_sub_unsigned(offset);
        let address = payload::AddressInfo {
            address,
            notify: reason == Reason::Notify,
            updiscon: reason == Reason::Updiscon,
            irdepth: None,
        };

        if self.state.branches.count() != 0 {
            Ok(payload::Branch {
                branch_map: self.state.branches.take(31),
                address: Some(address),
            }
            .into())
        } else {
            Ok(address.into())
        }
    }

    /// Issue a [`payload::Branch`] if the branch map is full
    ///
    /// Returns [`None`] if the branch does not contain at least 31 branches.
    pub fn report_full_branchmap(&mut self) -> Option<payload::Branch> {
        (self.branches() >= 31).then(|| payload::Branch {
            branch_map: self.state.branches.take(31),
            address: None,
        })
    }

    /// Determine the `branch` flag to include in sync payloads
    fn sync_branch_flag(&mut self) -> bool {
        if self.is_branch {
            let taken = self
                .state
                .branches
                .pop_taken()
                .expect("Branch map is empty when at least one branch is expected");
            self.is_branch = false;
            !taken
        } else {
            true
        }
    }
}

/// Reason an address payload is issued
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Reason {
    /// A notification was requested for the current address
    Notify,
    /// The current step lies between an updiscon and an event warranting resync
    ///
    /// The current instruction is immediately following an uninferable PC
    /// discontinuity and is the instruction just before an exception, privilege
    /// change or resync.
    Updiscon,
    /// The address payload is issued for another reason
    ///
    /// Other reasons include instructions following an uninferable PC
    /// discontinuity —without an exception, privilege change or resync
    /// following it.
    Other,
}
