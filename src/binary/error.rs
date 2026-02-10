// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Binary related error types and traits

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
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

#[cfg(feature = "alloc")]
impl Miss for Box<dyn MaybeMiss> {
    fn miss(address: u64) -> Self {
        Box::new(NoInstruction::miss(address))
    }
}

#[cfg(feature = "alloc")]
impl Miss for Box<dyn MaybeMissError> {
    fn miss(address: u64) -> Self {
        Box::new(NoInstruction::miss(address))
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
    /// Check whether this value indicates a miss
    ///
    /// This error value indicates that the [`Binary`][super::Binary] does not
    /// cover the address for which an [`Instruction`][super::Instruction] was
    /// requested.
    fn is_miss(&self) -> bool;
}

impl<T, E: MaybeMiss> MaybeMiss for Result<T, E> {
    fn is_miss(&self) -> bool {
        match self {
            Ok(_) => false,
            Err(e) => e.is_miss(),
        }
    }
}

#[cfg(feature = "alloc")]
impl<E: MaybeMiss + ?Sized> MaybeMiss for Box<E> {
    fn is_miss(&self) -> bool {
        E::is_miss(self.as_ref())
    }
}

#[cfg(feature = "either")]
impl<L: MaybeMiss, R: MaybeMiss> MaybeMiss for either::Either<L, R> {
    fn is_miss(&self) -> bool {
        either::for_both!(self, e => e.is_miss())
    }
}

/// [`MaybeMiss`] that is also an [`Error`][core::error::Error]
pub trait MaybeMissError: MaybeMiss + core::error::Error + Sync + Send {}

impl<T: MaybeMiss + core::error::Error + Sync + Send + ?Sized> MaybeMissError for T {}

/// An error for single segments of encoded [`Instruction`][super::Instruction]s
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SegmentError {
    /// The address was not covered
    AddressNotCovered,
    /// Could not use an address or offset because it is too big for the host
    ExceededHostUSize(core::num::TryFromIntError),
    /// An [`Instruction`][super::Instruction] could not be decoded
    InvalidInstruction,
}

impl Miss for SegmentError {
    fn miss(_: u64) -> Self {
        Self::AddressNotCovered
    }
}

impl MaybeMiss for SegmentError {
    fn is_miss(&self) -> bool {
        matches!(self, Self::AddressNotCovered)
    }
}

impl core::error::Error for SegmentError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::ExceededHostUSize(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for SegmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AddressNotCovered => write!(f, "Given address not covered"),
            Self::ExceededHostUSize(_) => write!(
                f,
                "An offset exceeds what can be represented with host native addresses"
            ),
            Self::InvalidInstruction => write!(f, "No valid instruction at address"),
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
