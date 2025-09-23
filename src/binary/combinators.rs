// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Combination of multiple [`Binary`]

use core::borrow::BorrowMut;

use crate::instruction::Instruction;

use super::error::{MaybeMiss, Miss};
use super::Binary;

/// Set of [`Binary`] acting as a single [`Binary`]
#[derive(Copy, Clone, Default, Debug)]
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

impl<C, B> Binary for Multi<C, B>
where
    C: BorrowMut<[B]>,
    B: Binary,
    B::Error: Miss,
{
    type Error = B::Error;

    fn get_insn(&mut self, address: u64) -> Result<Instruction, Self::Error> {
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
