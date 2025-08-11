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

/// A [`Binary`] that does not contain any [`Instruction`]s
#[derive(Copy, Clone, Default, Debug)]
pub struct Empty;

impl Binary for Empty {
    type Error = error::NoInstruction;

    fn get_insn(&mut self, _: u64) -> Result<Instruction, Self::Error> {
        Err(error::NoInstruction)
    }
}
