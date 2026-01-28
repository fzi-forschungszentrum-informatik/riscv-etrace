// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! [`Binary`] requiring [`Box`] and other types from alloc [`alloc`]

use alloc::boxed::Box;
use core::fmt;

use crate::instruction::{Instruction, info};

use super::Binary;
use super::error;

/// [`Binary`] returning a boxed, dynamically dispatched [`Error`]
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

impl<B, I> Binary<I> for BoxedError<B>
where
    B: Binary<I>,
    B::Error: error::MaybeMissError + 'static,
    I: info::Info,
{
    type Error = Error;

    fn get_insn(&mut self, address: u64) -> Result<Instruction<I>, Self::Error> {
        self.inner.get_insn(address).map_err(|e| Box::new(e).into())
    }
}

/// Dynamically dispatched error
#[derive(Debug)]
pub struct Error(Box<dyn error::MaybeMissError>);

impl<E: error::MaybeMissError + 'static> From<Box<E>> for Error {
    fn from(err: Box<E>) -> Self {
        Self(err)
    }
}

impl error::Miss for Error {
    fn miss(address: u64) -> Self {
        Self(Box::new(error::NoInstruction::miss(address)))
    }
}

impl error::MaybeMiss for Error {
    fn is_miss(&self) -> bool {
        error::MaybeMiss::is_miss(self.0.as_ref())
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        core::error::Error::source(self.0.as_ref())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.0.as_ref(), f)
    }
}
