// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Decoder-specific error types and utilities

use core::fmt;
use core::num::NonZeroUsize;

/// Decoder errors
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Error {
    /// The trace type is not known to us
    UnknownTraceType(u8),
    /// The format/subformat is unknown
    UnknownFmt(u8, Option<u8>),
    /// The branch format in a branch count payload is invalid
    BadBranchFmt,
    /// Some more bytes of data are required for the operation to succeed
    InsufficientData(NonZeroUsize),
    /// The privilege level is not known. You might want to implement it
    UnknownPrivilege(u8),
    /// Encountered an unknown encoder mode
    UnknownEncoderMode(u8),
}

impl core::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTraceType(t) => write!(f, "Unknown trace type {t}"),
            Self::UnknownFmt(t, None) => write!(f, "Unknown format {t}"),
            Self::UnknownFmt(t, Some(s)) => write!(f, "Unknown format,subformat {t},{s}"),
            Self::BadBranchFmt => write!(f, "Malformed branch format"),
            Self::InsufficientData(n) => write!(f, "At least {n} more bytes of data are required"),
            Self::UnknownPrivilege(p) => write!(f, "Unknown priviledge level {p}"),
            Self::UnknownEncoderMode(m) => write!(f, "Unknown encoder mode {m}"),
        }
    }
}
