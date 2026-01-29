// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Types not specific to [packets][crate::packet] or [tracer][crate::tracer]

pub mod branch;
pub mod stack;
pub mod trap;

#[cfg(test)]
mod tests;

use core::fmt;

/// RISC-V priviledge levels
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Hash)]
pub enum Privilege {
    #[default]
    User,
    Supervisor,
    Machine,
}

impl TryFrom<u8> for Privilege {
    type Error = u8;

    fn try_from(num: u8) -> Result<Self, Self::Error> {
        match num {
            0b00 => Ok(Self::User),
            0b01 => Ok(Self::Supervisor),
            0b11 => Ok(Self::Machine),
            err => Err(err),
        }
    }
}

impl From<Privilege> for u8 {
    fn from(p: Privilege) -> Self {
        match p {
            Privilege::User => 0b00,
            Privilege::Supervisor => 0b01,
            Privilege::Machine => 0b11,
        }
    }
}

impl fmt::Display for Privilege {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Privilege::User => write!(f, "U"),
            Privilege::Supervisor => write!(f, "S"),
            Privilege::Machine => write!(f, "M"),
        }
    }
}

/// Execution context
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct Context {
    /// The privilege level under which code is executed
    pub privilege: Privilege,
    /// The context of the execution
    pub context: u64,
}
