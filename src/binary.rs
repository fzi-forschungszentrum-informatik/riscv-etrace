// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Binaries containing [`Instruction`]s
//!
//! This module defines the [`Binary`] trait for programs that may be traced as
//! well as a number of types that may serve as a [`Binary`].

pub mod basic;
#[cfg(feature = "alloc")]
pub mod boxed;
pub mod combinators;
pub mod error;

#[cfg(feature = "elf")]
pub mod elf;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

pub use basic::{from_fn, from_map, from_sorted_map, Empty};
pub use combinators::Multi;

use crate::instruction::Instruction;

use error::Miss;

/// A binary of some sort that contains [`Instruction`]s
pub trait Binary {
    /// Error type returned by [`get_insn`][Self::get_insn]
    type Error;

    /// Retrieve the [`Instruction`] at the given address
    fn get_insn(&mut self, address: u64) -> Result<Instruction, Self::Error>;

    /// "Move" this binary by the given offset
    ///
    /// See [`Offset`] for more details.
    fn with_offset(self, offset: u64) -> Offset<Self>
    where
        Self: Sized,
        Self::Error: Miss,
    {
        Offset {
            inner: self,
            offset,
        }
    }

    /// Box this binary for dynamic dispatching
    ///
    /// This allows combining binaries of different types with (originally)
    /// different [`Error`][Self::Error] types in combinators such as [`Multi`].
    #[cfg(feature = "alloc")]
    fn boxed<'a>(self) -> BoxedBinary<'a>
    where
        Self: Sized + 'a,
        Self::Error: error::MaybeMissError + 'static,
    {
        Box::new(boxed::BoxedError::new(self))
    }
}

/// [`Binary`] implementation for a tuple of two binaries
///
/// The second [`Binary`] is considered a "patch" that is only consulted if the
/// first one did not yield an [`Instruction`]. Errors emitted always stem from
/// the first [`Binary`].
impl<B: Binary, P: Binary> Binary for (B, P) {
    type Error = B::Error;

    fn get_insn(&mut self, address: u64) -> Result<Instruction, Self::Error> {
        self.0
            .get_insn(address)
            .or_else(|e| self.1.get_insn(address).map_err(|_| e))
    }
}

impl<B> Binary for Option<B>
where
    B: Binary,
    B::Error: Miss,
{
    type Error = B::Error;

    fn get_insn(&mut self, address: u64) -> Result<Instruction, Self::Error> {
        self.as_mut()
            .map(|b| b.get_insn(address))
            .unwrap_or_else(|| Miss::miss(address))
    }
}

#[cfg(feature = "alloc")]
impl<B: Binary + ?Sized> Binary for Box<B> {
    type Error = B::Error;

    fn get_insn(&mut self, address: u64) -> Result<Instruction, Self::Error> {
        B::get_insn(self.as_mut(), address)
    }
}

/// [`Binary`] moved by a fixed offset
///
/// Accesses will be mapped by subtracting the fixed offset from the address.
/// Accesses to addresses lower than the offset will result in a [miss][Miss].
#[derive(Copy, Clone, Debug)]
pub struct Offset<B>
where
    B: Binary,
    B::Error: Miss,
{
    inner: B,
    offset: u64,
}

impl<B> Binary for Offset<B>
where
    B: Binary,
    B::Error: Miss,
{
    type Error = B::Error;

    fn get_insn(&mut self, address: u64) -> Result<Instruction, Self::Error> {
        address
            .checked_sub(self.offset)
            .ok_or(B::Error::miss(address))
            .and_then(|a| self.inner.get_insn(a))
    }
}

/// a [`Binary`] boxed for dynamic dispatch
#[cfg(feature = "alloc")]
pub type BoxedBinary<'a> = Box<dyn Binary<Error = Box<dyn error::MaybeMissError>> + 'a>;
