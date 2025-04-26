// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Configuration and utilities

#[cfg(feature = "serde")]
mod serde_utils;

use core::num::NonZeroU8;

/// Encoder parameters
///
/// These parameters to the encoder are defined in the specification. They
/// define the widths, and in some cases the presence or absence, of various
/// fields in packets decoded by the [decoder][crate::decoder] and sizes of
/// state that needs to be preserved by the [tracer][crate::tracer].
///
/// # Serde
///
/// If the `serde` feature is enabled, this type supports (de)serialization.
/// Note that flags of type `bool` such as [`notime_p`][Self::notime_p] are
/// (de)serialized to/from the numerical values `0` and `1` to be in line with
/// the specification.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Parameters {
    pub cache_size_p: u8,
    pub call_counter_size_p: u8,
    pub context_width_p: NonZeroU8,
    pub time_width_p: NonZeroU8,
    pub ecause_width_p: NonZeroU8,
    pub iaddress_lsb_p: NonZeroU8,
    pub iaddress_width_p: NonZeroU8,
    #[cfg_attr(feature = "serde", serde(with = "serde_utils::Flag"))]
    pub nocontext_p: bool,
    #[cfg_attr(feature = "serde", serde(with = "serde_utils::Flag"))]
    pub notime_p: bool,
    pub privilege_width_p: NonZeroU8,
    pub return_stack_size_p: u8,
    #[cfg_attr(feature = "serde", serde(with = "serde_utils::Flag"))]
    pub sijump_p: bool,
}

/// See [`PARAMETERS`] for default values of individual fields
impl Default for Parameters {
    fn default() -> Self {
        PARAMETERS
    }
}

/// Default [`Parameters`]
pub const PARAMETERS: Parameters = Parameters {
    cache_size_p: 0,
    call_counter_size_p: 0,
    context_width_p: NonZeroU8::MIN,
    time_width_p: NonZeroU8::MIN,
    ecause_width_p: NonZeroU8::new(6).unwrap(),
    iaddress_lsb_p: NonZeroU8::MIN,
    iaddress_width_p: NonZeroU8::new(32).unwrap(),
    nocontext_p: true,
    notime_p: true,
    privilege_width_p: NonZeroU8::new(2).unwrap(),
    return_stack_size_p: 0,
    sijump_p: false,
};

/// Address mode
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AddressMode {
    /// Any addresses is assumed to be a full, absolute addresses
    Full,
    /// An addresses is assumed to be relative to the previous address
    Delta,
}

impl AddressMode {
    /// Create an address mode from a [`bool`] indicating full address mode
    pub const fn from_full(full: bool) -> Self {
        if full {
            Self::Full
        } else {
            Self::Delta
        }
    }
}

impl Default for AddressMode {
    fn default() -> Self {
        Self::Delta
    }
}

/// Trace protocol version
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Version {
    V1,
    V2,
}

impl Default for Version {
    fn default() -> Self {
        Self::V2
    }
}
