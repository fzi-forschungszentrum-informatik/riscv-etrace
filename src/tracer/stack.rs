// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Return stack utiltities for infering function returns

/// Return stack
///
/// A stack of return addresses with a predefined maximal depth.
pub trait ReturnStack: Sized {
    /// Create a new return stack with the given maximum depth
    ///
    /// Returns `None` if `max_depth` is greater than the value supported by the
    /// implementaiton, or if the stack could not be created due to some other
    /// reason.
    fn new(max_depth: usize) -> Option<Self>;

    /// Push a new return address on the stack
    ///
    /// If the maximal depth is reached, the bottom address will be evicted from
    /// the stack and thus no longer be obtainable via a [Self::pop].
    fn push(&mut self, addr: u64);

    /// Retrieve and remove the topmost return address
    fn pop(&mut self) -> Option<u64>;

    /// Get the current stack depth
    fn depth(&self) -> usize;

    /// Get the maximum stack depth
    fn max_depth(&self) -> usize;
}

/// Statically allocated [ReturnStack]
///
/// This [ReturnStack] keeps data in an array of size `N`. It supports maximum
/// depths up to that size.
#[derive(Clone, Debug)]
pub struct StaticStack<const N: usize> {
    data: [u64; N],
    max_depth: usize,
    depth: usize,
    base: usize,
}

impl<const N: usize> ReturnStack for StaticStack<N> {
    fn new(max_depth: usize) -> Option<Self> {
        if max_depth > N {
            None
        } else {
            Some(Self {
                data: [0; N],
                max_depth,
                depth: 0,
                base: 0,
            })
        }
    }

    fn push(&mut self, addr: u64) {
        let depth = self.depth;
        self.data[(self.base + depth) % N] = addr;

        if depth < self.max_depth {
            self.depth = depth.saturating_add(1);
        } else {
            let base = self.base + 1;
            if base < N {
                self.base = base;
            } else {
                self.base = 0;
            }
        }
    }

    fn pop(&mut self) -> Option<u64> {
        let depth = self.depth.checked_sub(1)?;
        self.depth = depth;
        Some(self.data[(self.base + depth) % N])
    }

    fn depth(&self) -> usize {
        self.depth
    }

    fn max_depth(&self) -> usize {
        self.max_depth
    }
}

/// Dummy [ReturnStack] with zero depth
///
/// This [ReturnStack] does not hold any data. It only supports a maximum depth
/// of zero.
pub struct NoStack;

impl ReturnStack for NoStack {
    fn new(max_depth: usize) -> Option<Self> {
        (max_depth == 0).then_some(Self)
    }

    fn push(&mut self, _: u64) {}

    fn pop(&mut self) -> Option<u64> {
        None
    }

    fn depth(&self) -> usize {
        0
    }

    fn max_depth(&self) -> usize {
        0
    }
}
