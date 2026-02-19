// Copyright (C) 2025, 2026 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Trap related types and utilities

use core::fmt;

/// Information about a trap
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Info {
    /// Cause of the trap or interrupt
    pub ecause: u16,
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

impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ecause = self.ecause;
        match self.tval {
            Some(tval) => write!(f, "exception (ecause: {ecause}, tval: {tval:0x})"),
            None => write!(f, "interrupt (ecause: {ecause})"),
        }
    }
}
