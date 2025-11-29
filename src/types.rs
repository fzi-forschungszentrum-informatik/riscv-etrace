// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Types not specific to [packets][crate::packet] or [tracer][crate::tracer]

pub mod branch;
pub mod stack;
pub mod trap;

/// RISC-V priviledge levels
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Privilege {
    User,
    Supervisor,
    Machine,
}

impl Default for Privilege {
    fn default() -> Self {
        Self::User
    }
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

/// Execution context
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct Context {
    /// The privilege level under which code is executed
    pub privilege: Privilege,
    /// The context of the execution
    pub context: u64,
}
