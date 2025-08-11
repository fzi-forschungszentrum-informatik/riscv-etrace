// Copyright (C) 2024, 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Siemens Messaging Infrastructure packet header

use core::fmt;

use super::{payload, unit, Decode, Decoder, Error};

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

impl<U: unit::Unit> Decode<U> for Packet<U::IOptions, U::DOptions> {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        let payload_len: usize = decoder.read_bits(5)?;
        TraceType::decode(decoder)?;
        let time_tag = decoder
            .read_bit()?
            .then(|| decoder.read_bits(16))
            .transpose()?;
        let hart = decoder.read_bits(decoder.hart_index_width)?;
        decoder.advance_to_byte();
        decoder
            .decode_restricted(decoder.byte_pos() + payload_len)
            .map(|payload| Packet {
                time_tag,
                hart,
                payload,
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
