// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

pub mod branch;

/// RISC-V priviledge levels
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
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
