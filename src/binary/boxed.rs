// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! [`Binary`] requiring [`Box`] and other types from alloc [`alloc`]

use alloc::boxed::Box;

use crate::instruction::Instruction;

use super::error::MaybeMissError;
use super::Binary;

/// [`Binary`] returning a boxed, dynamically dispatched `Error`
///
/// This [`Binary`] adapter boxes and type-erases errors returned by the wrapped
/// [`Binary`]. This allows dynamically dispatching [`Binary`]s with differrent
/// [`Binary::Error`] types.
#[derive(Copy, Clone, Debug)]
pub struct BoxedError<B> {
    inner: B,
}

impl<B> BoxedError<B> {
    /// Create a new [`Binary`] wrapping another one
    pub fn new(inner: B) -> Self {
        Self { inner }
    }
}

impl<B> From<B> for BoxedError<B> {
    fn from(inner: B) -> Self {
        Self { inner }
    }
}

impl<B> Binary for BoxedError<B>
where
    B: Binary,
    B::Error: MaybeMissError + 'static,
{
    type Error = Box<dyn MaybeMissError>;

    fn get_insn(&mut self, address: u64) -> Result<Instruction, Self::Error> {
        self.inner
            .get_insn(address)
            .map_err(|e| -> Box<dyn MaybeMissError> { Box::new(e) })
    }
}
