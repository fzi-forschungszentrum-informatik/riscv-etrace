// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Payload generation errors

use core::fmt;

use crate::types::branch;

/// Errors that may be emitted during payload generation
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Packet generation requires a full address to be reported first
    NoAddressReported,
    /// Some (named) feature is not supported
    UnsupportedFeature(&'static str),
    /// Branch(es) could not be added to a [`branch::Map`]
    CannotAddBranches(branch::Error),
    /// The branch map is empty when it should not be
    BranchMapEmpty,
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::CannotAddBranches(inner) => Some(inner),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAddressReported => write!(f, "no previous address availible for delta"),
            Self::UnsupportedFeature(feat) => write!(f, "feature \"{feat}\" not supported"),
            Self::CannotAddBranches(_) => write!(f, "cannot add branches to branch map"),
            Self::BranchMapEmpty => write!(f, "the branch map is unexpectedly empty"),
        }
    }
}
