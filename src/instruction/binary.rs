// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

use core::fmt;

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

/// A [Binary] that does not contain any [Instruction]s
#[derive(Copy, Clone, Default, Debug)]
pub struct Empty;

impl Binary for Empty {
    type Error = NoInstruction;

    fn get_insn(&self, _: u64) -> Result<Instruction, Self::Error> {
        Err(NoInstruction)
    }
}

/// An error type expressing simple absence of an [Instruction]
#[derive(Copy, Clone, Debug)]
pub struct NoInstruction;

impl core::error::Error for NoInstruction {}

impl fmt::Display for NoInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "No Instruction availible")
    }
}
