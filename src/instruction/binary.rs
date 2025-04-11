// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

use core::fmt;

use super::Instruction;

/// A binary of some sort that contains [Instruction]s
pub trait Binary {
    /// Error type returned by [`get_insn`][Self::get_insn]
    type Error;

    /// Retrieve the [Instruction] at the given address
    fn get_insn(&mut self, address: u64) -> Result<Instruction, Self::Error>;
}

impl<F: FnMut(u64) -> Result<Instruction, E>, E> Binary for F {
    type Error = E;

    fn get_insn(&mut self, address: u64) -> Result<Instruction, Self::Error> {
        self(address)
    }
}

/// [Binary] implementation for mapping from address to [Instruction]
///
/// # Notice
///
/// This impl only functions correctly for slices that are sorted by address.
impl Binary for &[(u64, Instruction)] {
    type Error = NoInstruction;

    fn get_insn(&mut self, address: u64) -> Result<Instruction, Self::Error> {
        self.binary_search_by_key(&address, |(a, _)| *a)
            .map(|i| self[i].1)
            .map_err(|_| NoInstruction)
    }
}

/// [Binary] implementation for a tuple of two binaries
///
/// The second [Binary] is considered a "patch" that is only consulted if the
/// first one did not yield an [Instruction]. Errors emitted always stem from
/// the first [Binary].
impl<B: Binary, P: Binary> Binary for (B, P) {
    type Error = B::Error;

    fn get_insn(&mut self, address: u64) -> Result<Instruction, Self::Error> {
        self.0
            .get_insn(address)
            .or_else(|e| self.1.get_insn(address).map_err(|_| e))
    }
}

/// A [Binary] that does not contain any [Instruction]s
#[derive(Copy, Clone, Default, Debug)]
pub struct Empty;

impl Binary for Empty {
    type Error = NoInstruction;

    fn get_insn(&mut self, _: u64) -> Result<Instruction, Self::Error> {
        Err(NoInstruction)
    }
}

/// An error type expressing simple absence of an [Instruction]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NoInstruction;

impl core::error::Error for NoInstruction {}

impl fmt::Display for NoInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "No Instruction availible")
    }
}
