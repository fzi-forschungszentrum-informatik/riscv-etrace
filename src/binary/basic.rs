// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Basic [`Binary`]s and adapters

use crate::instruction::Instruction;

use super::error;
use super::Binary;

/// [`Binary`] adapter for an [`FnMut`]
///
/// This forwards calls to [`Binary::get_insn`] to the wrapped [`FnMut`].
#[derive(Copy, Clone, Default, Debug)]
pub struct Func<F: FnMut(u64) -> Result<Instruction, E>, E> {
    func: F,
    phantom: core::marker::PhantomData<E>,
}

impl<F: FnMut(u64) -> Result<Instruction, E>, E> Func<F, E> {
    /// Create a new [`Binary`] from an [`FnMut`]
    fn new(func: F) -> Self {
        Self {
            func,
            phantom: Default::default(),
        }
    }
}

impl<F: FnMut(u64) -> Result<Instruction, E>, E> Binary for Func<F, E> {
    type Error = E;

    fn get_insn(&mut self, address: u64) -> Result<Instruction, Self::Error> {
        (self.func)(address)
    }
}

/// Create a [`Func`] [`Binary`] from an [`FnMut`]
pub fn from_fn<F: FnMut(u64) -> Result<Instruction, E>, E>(func: F) -> Func<F, E> {
    Func::new(func)
}

/// A [`Binary`] that does not contain any [`Instruction`]s
#[derive(Copy, Clone, Default, Debug)]
pub struct Empty;

impl Binary for Empty {
    type Error = error::NoInstruction;

    fn get_insn(&mut self, _: u64) -> Result<Instruction, Self::Error> {
        Err(error::NoInstruction)
    }
}
