// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Configuration and utilities

/// Protocol configuration
///
/// A protocol configuration defines the bit widths, and in some cases the
/// presence, of the protocols packet fields as well as some options that are
/// relevant for the [tracer][crate::tracer::Tracer].
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Protocol {
    pub context_width_p: u8,
    pub time_width_p: u8,
    pub ecause_width_p: u8,
    pub iaddress_lsb_p: u8,
    pub iaddress_width_p: u8,
    pub cache_size_p: u8,
    pub privilege_width_p: u8,
    pub sijump_p: bool,
    pub call_counter_size_p: u8,
    pub return_stack_size_p: u8,
}

/// See [PROTOCOL] for default values of individual fields
impl Default for Protocol {
    fn default() -> Self {
        PROTOCOL
    }
}

/// Default [Protocol] configuration
pub const PROTOCOL: Protocol = Protocol {
    context_width_p: 0,
    time_width_p: 0,
    ecause_width_p: 6,
    iaddress_lsb_p: 1,
    iaddress_width_p: 32,
    cache_size_p: 0,
    privilege_width_p: 2,
    sijump_p: false,
    call_counter_size_p: 0,
    return_stack_size_p: 0,
};

/// Address mode
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AddressMode {
    /// Any addresses is assumed to be a full, absolute addresses
    Full,
    /// An addresses is assumed to be relative to the previous address
    Delta,
}

impl Default for AddressMode {
    fn default() -> Self {
        Self::Delta
    }
}
