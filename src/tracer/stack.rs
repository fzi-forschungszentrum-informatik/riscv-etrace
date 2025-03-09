// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

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
