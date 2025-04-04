// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

use core::fmt;

/// Tracing specific errors
#[derive(Debug, PartialEq, Eq)]
pub enum Error<I> {
    /// Address provided by packet is zero
    ///
    /// The PC cannot be set to the address, as the address is 0.
    AddressIsZero,
    /// Invalid input at start of trace
    ///
    /// The tracer requires a synchronization packet as the first packet.
    StartOfTrace,
    /// Unprocessed branches left
    ///
    /// Some number of branches which should have been processed are still
    /// unprocessed.
    UnprocessedBranches(core::num::NonZeroU8),
    /// An unexpected uninferable discontinuity was encountered
    UnexpectedUninferableDiscon,
    /// The tracer cannot resolve some branch
    ///
    /// The tracer has exhausted all availible branch information.
    UnresolvableBranch,
    /// The current synchronization packet has no branching information
    WrongGetBranchType,
    /// The current packet has no privilege information
    WrongGetPrivilegeType,
    /// The IR stack cannot be constructed for the given size
    CannotConstructIrStack(usize),
    /// We could not fetch an `Instruction` from a given address
    CannotGetInstruction(I, u64),
}

impl<I> core::error::Error for Error<I>
where
    I: fmt::Debug + core::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::CannotGetInstruction(inner, _) => Some(inner),
            _ => None,
        }
    }
}

impl<I> fmt::Display for Error<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AddressIsZero => write!(f, "address is zero"),
            Self::StartOfTrace => write!(f, "expected sync packet"),
            Self::UnprocessedBranches(c) => write!(f, "{c} unprocessed branches"),
            Self::UnexpectedUninferableDiscon => write!(f, "unexpected uninferable discontinuity"),
            Self::UnresolvableBranch => write!(f, "unresolvable branch"),
            Self::WrongGetBranchType => write!(f, "expected branching info in packet"),
            Self::WrongGetPrivilegeType => write!(f, "expected privilege info in packet"),
            Self::CannotConstructIrStack(size) => {
                write!(f, "Cannot construct return stack of size {size}")
            }
            Self::CannotGetInstruction(_, addr) => {
                write!(f, "Cannot get the instruction at {addr:#0x}")
            }
        }
    }
}
