// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Trap related types and utilities

/// Information about a trap
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Info {
    /// Cause of the trap or interrupt
    pub ecause: u64,
    /// Appropriate `utval`/`stval`/`vstval`/`mtval`
    ///
    /// This field also indicates whether the trap is an interrupt (`None`) or
    /// exception (`Some`).
    pub tval: Option<u64>,
}

impl Info {
    /// This info refers to an interrupt
    pub fn is_interrupt(&self) -> bool {
        self.tval.is_none()
    }

    /// This info refers to an exception
    pub fn is_exception(&self) -> bool {
        self.tval.is_some()
    }
}
