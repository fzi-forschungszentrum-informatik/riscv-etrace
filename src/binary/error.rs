// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Binary related error types and traits

use core::fmt;

/// A [`MaybeMiss`] allowing the construction of a miss
pub trait Miss: MaybeMiss {
    /// Construct a value indicating a miss
    ///
    /// This error value indicates that the [`Binary`][super::Binary] does not
    /// cover the given `address`.
    fn miss(address: u64) -> Self;
}

impl<T, E: Miss> Miss for Result<T, E> {
    fn miss(address: u64) -> Self {
        Err(<E as Miss>::miss(address))
    }
}

/// May indicate that an address is not covered by a [`Binary`][super::Binary]
///
/// A [`Binary`][super::Binary] usually only covers a subset of all possible
/// addresses, e.g. a memory area on the target device. Requesting an
/// [`Instruction`][super::Instruction] at an addresses outside that area will
/// naturally yield an error. This trait allows identifying these particular
/// errors.
pub trait MaybeMiss {
    /// Construct a value indicating a miss
    ///
    /// This error value indicates that the [`Binary`][super::Binary] does not
    /// cover the given `address`.
    fn miss(address: u64) -> Self;

    /// Check whether this value indicates a miss
    ///
    /// This error value indicates that the [`Binary`][super::Binary] does not
    /// cover the address for which an [`Instruction`][super::Instruction] was
    /// requested.
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

/// An error type expressing absence of an [`Instruction`][super::Instruction]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NoInstruction;

impl Miss for NoInstruction {
    fn miss(_: u64) -> Self {
        NoInstruction
    }
}

impl MaybeMiss for NoInstruction {
    fn miss(_: u64) -> Self {
        NoInstruction
    }

    fn is_miss(&self) -> bool {
        true
    }
}

impl core::error::Error for NoInstruction {}

impl fmt::Display for NoInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "No Instruction availible")
    }
}
