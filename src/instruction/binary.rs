// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

use super::Instruction;

/// A binary of some sort that contains [Instruction]s
pub trait Binary {
    /// Error type returned by [`get_insn`][Self::get_insn]
    type Error;

    /// Retrieve the [Instruction] at the given address
    fn get_insn(&self, address: u64) -> Result<Instruction, Self::Error>;
}

impl<F: Fn(u64) -> Result<Instruction, E>, E> Binary for F {
    type Error = E;

    fn get_insn(&self, address: u64) -> Result<Instruction, Self::Error> {
        self(address)
    }
}
