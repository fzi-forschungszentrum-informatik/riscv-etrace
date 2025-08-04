// Copyright (C) 2024, 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Siemens Messaging Infrastructure packet header

use core::fmt;

use super::{payload, Decode, Decoder, Error};

/// A Siemens Messaging Infrastructure (SMI) Packet
///
/// This type represents a decoded Siemens Messaging Infrastructure (SMI) Packet
/// as described in Chapter 7. Instruction Trace Encoder Output Packets of the
/// specification. A packet consists of SMI specific header information, and an
/// SMI-independent tracing [`Payload`][payload::Payload].
#[derive(Debug)]
pub struct Packet<I, D> {
    /// Partial time stamp
    pub time_tag: Option<u16>,
    /// Index of the hart this packet is originating from
    ///
    /// The index specifies the address of the hart's trace unit within the
    /// messaging infrastructure. It may not be identical to the value of the
    /// `mhartid` CSR for that hart.
    pub hart: u64,
    /// The packet payload
    pub payload: payload::Payload<I, D>,
}

/// Siemens Messaging Infrastructure Packet header
///
/// This type represents a decoded header of a Siemens Messaging Infrastructure
/// (SMI) Packet as described in Chapter 7. Instruction Trace Encoder Output
/// Packets of the specification.
#[derive(Debug, Eq, PartialEq)]
pub struct Header {
    /// [`Payload`][payload::Payload] length in bytes.
    pub payload_len: usize,
    /// Destination flow indicator, which we use for the trace type
    pub trace_type: TraceType,
    /// Partial time stamp
    pub time_tag: Option<u16>,
    /// Index of the hart this packet is originating from
    ///
    /// The index specifies the address of the hart's trace unit within the
    /// messaging infrastructure. It may not be identical to the value of the
    /// `mhartid` CSR for that hart.
    pub hart_index: usize,
}

impl<U> Decode<U> for Header {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        let payload_len = decoder.read_bits(5)?;
        let trace_type = TraceType::decode(decoder)?;
        let time_tag = decoder
            .read_bit()?
            .then(|| decoder.read_bits(16))
            .transpose()?;
        let hart_index = decoder.read_bits(decoder.hart_index_width)?;

        Ok(Header {
            payload_len,
            trace_type,
            time_tag,
            hart_index,
        })
    }
}

/// Destination flow indicator, which we use for the trace type
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TraceType {
    /// The packet contains an instruction trace payload
    Instruction,
}

impl fmt::Display for TraceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Instruction => write!(f, "Instruction"),
        }
    }
}

impl<U> Decode<U> for TraceType {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        match decoder.read_bits::<u8>(2)? {
            0b10 => Ok(TraceType::Instruction),
            unknown => Err(Error::UnknownTraceType(unknown)),
        }
    }
}
