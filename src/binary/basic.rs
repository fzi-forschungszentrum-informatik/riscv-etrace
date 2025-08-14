// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Basic [`Binary`]s and adapters

use crate::instruction::{base, Instruction};

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

/// [`Binary`] consisting of a single segment of encoded [`Instruction`]s
///
/// This [`Binary`] serves a single buffer as a code segment starting from
/// address `0`.
///
/// # Example
///
/// The following example builds a segment at a specifig offset:
///
/// ```
/// use riscv_etrace::binary::{self, Binary};
/// use riscv_etrace::instruction::{self, base};
///
/// let bootrom = b"\x97\x02\x00\x00\x93\x85\x02\x02\x73\x25\x40\xf1\x83\xb2\x82\x01\x67\x80\x02\x00";
/// let mut bootrom = binary::from_segment(bootrom, base::Set::Rv64I)
///     .with_offset(0x1000);
/// assert_eq!(
///     bootrom.get_insn(0x1010),
///     Ok(instruction::Kind::new_jalr(0, 5, 0).into()),
/// );
/// ```
#[derive(Copy, Clone, Debug)]
pub struct Segment<T: AsRef<[u8]>> {
    data: T,
    base: base::Set,
}

impl<T: AsRef<[u8]>> Segment<T> {
    /// Create a new [`Binary`] for code of a given instruction [`base::Set`]
    pub fn new(data: T, base: base::Set) -> Self {
        Self { data, base }
    }
}

impl<T: AsRef<[u8]>> Binary for Segment<T> {
    type Error = error::SegmentError;

    fn get_insn(&mut self, address: u64) -> Result<Instruction, Self::Error> {
        let offset = address.try_into().map_err(Self::Error::ExceededHostUSize)?;
        let insn_data = self
            .data
            .as_ref()
            .split_at_checked(offset)
            .map(|(_, d)| d)
            .filter(|d| !d.is_empty())
            .ok_or(Self::Error::AddressNotCovered)?;
        Instruction::extract(insn_data, self.base)
            .map(|(i, _)| i)
            .ok_or(Self::Error::InvalidInstruction)
    }
}

/// [`Binary`] defined by a set of addresses-[`Instruction`] pairs
///
/// This [`Binary`] is backed by a slice of addresses-[`Instruction`] pairs
/// specifying the presence of an [`Instruction`] at the specified address. The
/// [`Binary`] is meant for small, fixed code sequences such as bootroms.
#[derive(Copy, Clone, Default, Debug)]
pub struct SimpleMap<T: AsRef<[(u64, Instruction)]>> {
    inner: T,
}

impl<T: AsRef<[(u64, Instruction)]>> SimpleMap<T> {
    /// Create a new [`Binary`], potentially from a different type of container
    ///
    /// Prepares the slice held by the given container, then converts this to
    /// the target type and returns the [`Binary`] contructed from that. This
    /// allows creating a [`Binary`] operating on an [`Arc`][alloc::sync::Arc]
    /// from containers that allow mutation of the slice such as
    /// [`Box`][alloc::boxed::Box].
    pub fn new<I>(mut inner: I) -> Self
    where
        T: From<I>,
        I: AsMut<[(u64, Instruction)]>,
    {
        inner.as_mut().sort_unstable_by_key(|(a, _)| *a);
        Self {
            inner: inner.into(),
        }
    }

    /// Create a [`Binary`] from a container holding a sorted slice
    ///
    /// Returns [`None`] if the slice is not sorted by address.
    pub fn from_sorted(inner: T) -> Option<Self> {
        inner
            .as_ref()
            .is_sorted_by_key(|(a, _)| *a)
            .then_some(Self { inner })
    }
}

impl<T, I> From<I> for SimpleMap<T>
where
    T: AsRef<[(u64, Instruction)]> + From<I>,
    I: AsMut<[(u64, Instruction)]>,
{
    fn from(inner: I) -> Self {
        Self::new(inner)
    }
}

impl<T: AsRef<[(u64, Instruction)]>> Binary for SimpleMap<T> {
    type Error = error::NoInstruction;

    fn get_insn(&mut self, address: u64) -> Result<Instruction, Self::Error> {
        let map = self.inner.as_ref();
        map.binary_search_by_key(&address, |(a, _)| *a)
            .map(|i| map[i].1)
            .map_err(|_| error::NoInstruction)
    }
}

/// Create a [`Func`] [`Binary`] from some `AsRef<[(u64, Instruction)]>`
///
/// Returns `None` if the address-[`Instruction`] pairs are not sorted by
/// address.
pub fn from_sorted_map<T: AsRef<[(u64, Instruction)]>>(inner: T) -> Option<SimpleMap<T>> {
    SimpleMap::from_sorted(inner)
}

/// Create a [`Func`] [`Binary`] from some `AsMut<[(u64, Instruction)]>`
pub fn from_map<T, I>(inner: I) -> SimpleMap<T>
where
    T: AsRef<[(u64, Instruction)]> + From<I>,
    I: AsMut<[(u64, Instruction)]>,
{
    inner.into()
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
