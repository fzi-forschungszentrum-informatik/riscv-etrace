// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Combination of multiple [`Binary`]

use core::borrow::BorrowMut;

use crate::instruction::Instruction;

use super::error::{MaybeMiss, Miss};
use super::Binary;

/// Set of [`Binary`] acting as a single [`Binary`]
#[derive(Copy, Clone, Default, Debug)]
pub struct Multi<C, B>
where
    C: BorrowMut<[B]>,
    B: Binary,
    B::Error: Miss,
{
    bins: C,
    last: usize,
    phantom: core::marker::PhantomData<B>,
}

impl<C, B> Multi<C, B>
where
    C: BorrowMut<[B]>,
    B: Binary,
    B::Error: Miss,
{
    /// Create a new [`Binary`] combining all `bins`
    pub fn new(bins: C) -> Self {
        Self {
            bins,
            last: 0,
            phantom: Default::default(),
        }
    }
}

impl<C, B> From<C> for Multi<C, B>
where
    C: BorrowMut<[B]>,
    B: Binary,
    B::Error: Miss,
{
    fn from(bins: C) -> Self {
        Self::new(bins)
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
