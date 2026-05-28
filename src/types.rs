// Copyright (C) 2025, 2026 FZI Forschungszentrum Informatik
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
    Debug,
    VirtUser,
    VirtSupervisor,
}

impl TryFrom<u8> for Privilege {
    type Error = u8;

    fn try_from(num: u8) -> Result<Self, Self::Error> {
        match num {
            0 => Ok(Self::User),
            1 => Ok(Self::Supervisor),
            3 => Ok(Self::Machine),
            4 => Ok(Self::Debug),
            5 => Ok(Self::VirtUser),
            6 => Ok(Self::VirtSupervisor),
            err => Err(err),
        }
    }
}

impl From<Privilege> for u8 {
    fn from(p: Privilege) -> Self {
        match p {
            Privilege::User => 0,
            Privilege::Supervisor => 1,
            Privilege::Machine => 3,
            Privilege::Debug => 4,
            Privilege::VirtUser => 5,
            Privilege::VirtSupervisor => 6,
        }
    }
}

impl fmt::Display for Privilege {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Privilege::User => write!(f, "U"),
            Privilege::Supervisor => write!(f, "S"),
            Privilege::Machine => write!(f, "M"),
            Privilege::Debug => write!(f, "D"),
            Privilege::VirtUser => write!(f, "VU"),
            Privilege::VirtSupervisor => write!(f, "VS"),
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
