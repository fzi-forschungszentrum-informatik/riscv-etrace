// Copyright (C) 2025, 2026 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Combination of multiple [`Binary`]

use core::borrow::{Borrow, BorrowMut};

use crate::instruction::{Instruction, info};

use super::Binary;
use super::error::{MaybeMiss, Miss};

/// Set of [`Binary`] acting as a single [`Binary`]
#[derive(Copy, Clone, Debug)]
pub struct Multi<C: BorrowMut<[B]>, B> {
    bins: C,
    last: usize,
    phantom: core::marker::PhantomData<B>,
}

impl<C: BorrowMut<[B]>, B> Multi<C, B> {
    /// Create a new [`Binary`] combining all `bins`
    pub fn new(bins: C) -> Self {
        Self {
            bins,
            last: 0,
            phantom: Default::default(),
        }
    }
}

/// Accessors
impl<C: Borrow<[B]> + BorrowMut<[B]>, B> Multi<C, B> {
    /// Retrieve the inner [`Binary`]s
    pub fn inner(&self) -> &[B] {
        self.bins.borrow()
    }

    /// Retrieve an iterator over all inner [`Binary`]s
    pub fn iter(&self) -> core::slice::Iter<'_, B> {
        self.inner().iter()
    }
}

impl<C: BorrowMut<[B]> + Default, B> Default for Multi<C, B> {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl<C: BorrowMut<[B]>, B> From<C> for Multi<C, B> {
    fn from(bins: C) -> Self {
        Self::new(bins)
    }
}

impl<C: BorrowMut<[B]> + FromIterator<B>, B> FromIterator<B> for Multi<C, B> {
    fn from_iter<T: IntoIterator<Item = B>>(iter: T) -> Self {
        C::from_iter(iter).into()
    }
}

impl<C: BorrowMut<[B]> + Extend<B>, B> Extend<B> for Multi<C, B> {
    fn extend<T: IntoIterator<Item = B>>(&mut self, iter: T) {
        self.bins.extend(iter)
    }
}

impl<C, B, I> Binary<I> for Multi<C, B>
where
    C: BorrowMut<[B]>,
    B: Binary<I>,
    B::Error: Miss,
    I: info::Info,
{
    type Error = B::Error;

    fn get_insn(&mut self, address: u64) -> Result<Instruction<I>, Self::Error> {
        let bins = self.bins.borrow_mut();
        let res = bins
            .get_mut(self.last)
            .map(|b| b.get_insn(address))
            .filter(|r| !r.is_miss());
        if let Some(res) = res {
            return res;
        }

        let res = bins
            .iter_mut()
            .enumerate()
            .filter(|(n, _)| *n != self.last)
            .map(|(n, b)| (n, b.get_insn(address)))
            .find(|(_, r)| !r.is_miss());
        if let Some((current, res)) = res {
            self.last = current;
            res
        } else {
            Miss::miss(address)
        }
    }
}
