// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Binaries containing [`Instruction`]s
//!
//! Tracing requires knowledge about the program being traced. This module
//! defines the [`Binary`] trait used by the [`Tracer`][super::tracer::Tracer]
//! for retrieving [`Instruction`]s as well as a number of types implementing
//! the [`Binary`] trait. These include:
//!
//! * some [basic] [`Binary`]s such as adapters that may be created through
//!   free fns such as [`from_fn`] and [`from_segment`] and allow defining
//!   [`Binary`]s from a wide range of types supplying data,
//! * [combinators] that allow tracing multiple programs or program parts such
//!   as a firmware and an appliction,
//! * modifiers such as [`Offset`] that are usually created through provided fns
//!   of the [`Binary`] trait and
//! * feature-dependent [`Binary`]s, e.g. for using [ELF][elf] files as
//!   [`Binary`]s.
//!
//! # Combining [`Binary`]s
//!
//! Usually, [`Binary`]s used in [combinators] all need to agree on the
//! [`Binary::Error`] type. Combinators such as [`Multi`] in particular also
//! requires the [`Binary`]s themselves to be of the same type. If the `alloc`
//! feature is enabled, the error type may be erased through the provided method
//! [`Binary::boxed`]. The lifetime of the original [`Binary`] is preserved in
//! the resulting [`boxed::Binary`]. This is relevant when using an [`elf::Elf`]
//! or when...
//!
//! # Sharing [`Binary`]s between [`Tracer`] instances
//!
//! [`Binary`]s are intended for use by a single [`Tracer`] and can not be
//! easily shared between instances. They may be mutated when fetching an
//! [`Instruction`], e.g. for caching purposes. For example, a [`Multi`] will
//! remember the [`Binary`] it chooses and pick that particular one first the
//! next time.
//!
//! Sharing a [`Binary`] between [`Tracer`]s by placing them behind a mutex of
//! some kind defeates the caching, incurs considerable overhead and is highly
//! discouraged. Instead, users should consider sharing the data backing the
//! [`Binary`]s. For example, a [`basic::Segment`] may be created from a shared
//! buffer or [`Arc`][alloc::sync::Arc] and then cloned.
//!
//! # Example
//!
//! The following constructs a [`Binary`] from a firmware image and a bootrom
//! and clones it for use by a second [`Tracer`] instance.
//!
//! ```
//! use riscv_etrace::binary::{self, Binary, Multi};
//! use riscv_etrace::instruction::base;
//!
//! # let bootrom = b"\x97\x02\x00\x00\x93\x85\x02\x02\x73\x25\x40\xf1\x83\xb2\x82\x01\x67\x80\x02\x00";
//! # let firmware = b"\x97\x02\x00\x00\x93\x82\x02\x00\x73\xa0\x52\x30\x73\x00\x50\x10\x6f\xf0\xdf\xff";
//! let binary1 = Multi::new([
//!     binary::from_segment(bootrom, base::Set::Rv32I).with_offset(0x1000),
//!     binary::from_segment(firmware, base::Set::Rv32I).with_offset(0x80000000),
//! ]);
//! let binary2 = binary1.clone();
//! ```
//!
//! [`Tracer`]: [super::tracer::Tracer]

pub mod basic;
#[cfg(feature = "alloc")]
pub mod boxed;
pub mod combinators;
#[cfg(feature = "elf")]
pub mod elf;
pub mod error;

#[cfg(test)]
mod tests;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

pub use basic::{Empty, from_fn, from_map, from_segment, from_sorted_map};
pub use combinators::Multi;

use crate::instruction::{self, Instruction};

use error::Miss;
use instruction::info::Info;

/// A binary of some sort that contains [`Instruction`]s
///
/// See the [module level][self] documentation for more details.
pub trait Binary<I: Info> {
    /// Error type returned by [`get_insn`][Self::get_insn]
    type Error;

    /// Retrieve the [`Instruction`] at the given address
    fn get_insn(&mut self, address: u64) -> Result<Instruction<I>, Self::Error>;

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
    /// different [`Error`][Self::Error] types in [combinators].
    #[cfg(feature = "alloc")]
    fn boxed<'a>(self) -> boxed::Binary<'a, I>
    where
        Self: Sized + 'a,
        Self::Error: error::MaybeMissError + 'static,
    {
        Box::new(boxed::BoxedError::new(self))
    }
}

/// [`Binary`] implementation for a tuple of two binaries
///
/// This impl allows combining [`Binary`]s as long as they agree on their error
/// type. If the first [`Binary`] returns a "miss", the second one is consulted.
impl<A, B, I, E> Binary<I> for (A, B)
where
    A: Binary<I, Error = E>,
    B: Binary<I, Error = E>,
    I: Info,
    E: error::MaybeMiss,
{
    type Error = B::Error;

    fn get_insn(&mut self, address: u64) -> Result<Instruction<I>, Self::Error> {
        use error::MaybeMiss;

        let res = self.0.get_insn(address);
        if res.is_miss() {
            self.1.get_insn(address)
        } else {
            res
        }
    }
}

impl<B, I> Binary<I> for Option<B>
where
    B: Binary<I>,
    B::Error: Miss,
    I: Info,
{
    type Error = B::Error;

    fn get_insn(&mut self, address: u64) -> Result<Instruction<I>, Self::Error> {
        self.as_mut()
            .map(|b| b.get_insn(address))
            .unwrap_or_else(|| Miss::miss(address))
    }
}

#[cfg(feature = "alloc")]
impl<B: Binary<I> + ?Sized, I: Info> Binary<I> for Box<B> {
    type Error = B::Error;

    fn get_insn(&mut self, address: u64) -> Result<Instruction<I>, Self::Error> {
        B::get_insn(self.as_mut(), address)
    }
}

#[cfg(feature = "either")]
impl<L, R, I, E> Binary<I> for either::Either<L, R>
where
    L: Binary<I, Error = E>,
    R: Binary<I, Error = E>,
    I: Info,
{
    type Error = E;

    fn get_insn(&mut self, address: u64) -> Result<Instruction<I>, Self::Error> {
        either::for_both!(self, b => b.get_insn(address))
    }
}

/// [`Binary`] moved by a fixed offset
///
/// Accesses will be mapped by subtracting the fixed offset from the address.
/// Accesses to addresses lower than the offset will result in a [miss][Miss].
#[derive(Copy, Clone, Debug)]
pub struct Offset<B> {
    inner: B,
    offset: u64,
}

impl<B> Offset<B> {
    /// Retrieve the inner [`Binary`]
    pub fn inner(&self) -> &B {
        &self.inner
    }

    /// Retrieve the offset
    pub fn offset(&self) -> u64 {
        self.offset
    }
}

impl<B, I> Binary<I> for Offset<B>
where
    B: Binary<I>,
    B::Error: Miss,
    I: Info,
{
    type Error = B::Error;

    fn get_insn(&mut self, address: u64) -> Result<Instruction<I>, Self::Error> {
        address
            .checked_sub(self.offset)
            .ok_or(B::Error::miss(address))
            .and_then(|a| self.inner.get_insn(a))
    }
}

/// A [`Binary`] which may be sent or synced between threads
pub trait SyncBinary<I: Info>: Binary<I> + Send + Sync {}

impl<I: Info, T: Binary<I> + Send + Sync> SyncBinary<I> for T {}
