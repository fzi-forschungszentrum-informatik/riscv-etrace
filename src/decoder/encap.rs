// Copyright (C) 2024, 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Types and utilities for the RISC-V Encapsulation specification
//!
//! This module provides types and utilities for processing packets following
//! the [Unformatted Trace & Diagnostic Data Packet Encapsulation for
//! RISC-V][encap] specification.
//!
//! [encap]: <https://github.com/riscv-non-isa/e-trace-encap/>

use super::{payload, unit, Decode, Decoder, Error};

/// Normal RISC-V Encapsulation packet
///
/// This datatype represents a "Normal Encapsulation Structure" as describes in
/// Chapter 2.1 of the Encapsulation specification.
///
/// This type encapsulates a [`Decoder`], from which it will consume all
/// associated when [dropped][Drop::drop], leaving the decoder at the byte
/// boundary following the packet. Thus, the packet's data will be consumed
/// regardless of whether the payload was decoded or not and even if an error
/// occurred while decoding the payload.
pub struct Normal<'a, 'd, U> {
    flow: u8,
    src_id: u16,
    timestamp: Option<u64>,
    decoder: &'a mut Decoder<'d, U>,
    remaining: &'d [u8],
}

impl<'a, 'd, U> Normal<'a, 'd, U> {
    /// Retrieve the flow indicator of this packet
    pub fn flow(&self) -> u8 {
        self.flow
    }

    /// Retrieve the packet's source id
    ///
    /// Identifies the source (e.g. Trace encoder associated to a specific HART)
    /// of the packet.
    pub fn src_id(&self) -> u16 {
        self.src_id
    }

    /// Retrieve the packet's (outer) timestamp
    pub fn timestamp(&self) -> Option<u64> {
        self.timestamp
    }
}

impl<'a, 'd, U: unit::Unit> Normal<'a, 'd, U> {
    /// Decode the packet's ETrace payload
    pub fn payload(self) -> Result<Payload<U::IOptions, U::DOptions>, Error> {
        Decode::decode(self.decoder)
    }
}

impl<'a, 'd, U> Drop for Normal<'a, 'd, U> {
    fn drop(&mut self) {
        self.decoder.reset(self.remaining);
    }
}

/// ETrace payload of an Encapsulation packet
///
/// This datatype represents a payload as describes in Chapter 2.1.4 and Chapter
/// 3.3 of the Encapsulation specification.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Payload<I, D> {
    InstructionTrace(payload::Payload<I, D>),
    DataTrace,
}

impl<I, D> Payload<I, D> {
    /// Retrieve the encapsulated instruction trace payload
    ///
    /// Returns [None] if this payload is not an instruction trace payload.
    pub fn as_instruction_trace(&self) -> Option<&payload::Payload<I, D>> {
        match self {
            Payload::InstructionTrace(p) => Some(p),
            _ => None,
        }
    }
}

impl<I, D> From<payload::Payload<I, D>> for Payload<I, D> {
    fn from(p: payload::Payload<I, D>) -> Self {
        Self::InstructionTrace(p)
    }
}

impl<I, D> TryFrom<Payload<I, D>> for payload::Payload<I, D> {
    type Error = Payload<I, D>;

    fn try_from(payload: Payload<I, D>) -> Result<Self, Self::Error> {
        match payload {
            Payload::InstructionTrace(p) => Ok(p),
            p => Err(p),
        }
    }
}

impl<U: unit::Unit> Decode<'_, '_, U> for Payload<U::IOptions, U::DOptions> {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        match decoder.read_bits::<u8>(decoder.trace_type_width)? {
            0 => Decode::decode(decoder).map(Self::InstructionTrace),
            unknown => Err(Error::UnknownTraceType(unknown)),
        }
    }
}
