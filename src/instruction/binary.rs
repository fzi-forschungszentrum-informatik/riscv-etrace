// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Binaries containing [`Instruction`]s
//!
//! This module defines the [`Binary`] trait for programs that may be traced as
//! well as a number of types that may serve as a [`Binary`].

use core::fmt;

use super::Instruction;

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
    {
        Offset {
            inner: self,
            offset,
        }
    }
}

impl<F: FnMut(u64) -> Result<Instruction, E>, E> Binary for F {
    type Error = E;

    fn get_insn(&mut self, address: u64) -> Result<Instruction, Self::Error> {
        self(address)
    }
}

/// [`Binary`] implementation for mapping from address to [`Instruction`]
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

/// [`Binary`] moved by a fixed offset
///
/// Accesses will be mapped by subtracting the fixed offset from the address.
/// The subtraction is done in a wrapping fashion, i.e. accesses to addresses
/// lower than the offset will translate to accesses to higher addresses.
#[derive(Copy, Clone, Debug)]
pub struct Offset<B: Binary> {
    inner: B,
    offset: u64,
}

impl<B: Binary> Binary for Offset<B> {
    type Error = B::Error;

    fn get_insn(&mut self, address: u64) -> Result<Instruction, Self::Error> {
        self.inner.get_insn(address.wrapping_sub(self.offset))
    }
}

/// A [`Binary`] that does not contain any [`Instruction`]s
#[derive(Copy, Clone, Default, Debug)]
pub struct Empty;

impl Binary for Empty {
    type Error = NoInstruction;

    fn get_insn(&mut self, _: u64) -> Result<Instruction, Self::Error> {
        Err(NoInstruction)
    }
}

/// An error that may indicate that an address is not covered by a [`Binary`]
///
/// A [`Binary`] usually only provides [`Instruction`]s for a subset of all
/// possible addresses, e.g. a memory area on the target device. Requesting
/// [`Instruction`]s at addresses outside that area will naturally yield an
/// error. This trait allows identifying these particular errors.
pub trait MaybeMiss {
    /// Construct a value indicating a miss
    ///
    /// This error value indicates that the [`Binary`] does not cover the
    /// given `address`.
    fn miss(address: u64) -> Self;

    /// Check whether this value indicates a miss
    ///
    /// This error value indicates that the [`Binary`] does not cover the
    /// address for which an [`Instruction`] was requested.
    fn is_miss(&self) -> bool;
}

impl<T, E: MaybeMiss> MaybeMiss for Result<T, E> {
    fn miss(address: u64) -> Self {
        Err(E::miss(address))
    }

    fn is_miss(&self) -> bool {
        match self {
            Ok(_) => false,
            Err(e) => e.is_miss(),
        }
    }
}

/// An error type expressing simple absence of an [`Instruction`]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NoInstruction;

impl core::error::Error for NoInstruction {}

impl fmt::Display for NoInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "No Instruction availible")
    }
}
