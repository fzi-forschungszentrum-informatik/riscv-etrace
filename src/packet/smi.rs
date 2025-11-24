// Copyright (C) 2024, 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Siemens Messaging Infrastructure packet header

use core::fmt;

use super::decoder::{self, Decode, Decoder};
use super::{payload, unit, Error};

/// A Siemens Messaging Infrastructure (SMI) Packet
///
/// This type represents a decoded Siemens Messaging Infrastructure (SMI) Packet
/// as described in Chapter 7. Instruction Trace Encoder Output Packets of the
/// specification. A packet consists of SMI specific header information, and an
/// SMI-independent [`InstructionTrace`][payload::InstructionTrace] payload.
#[derive(Debug, PartialEq)]
pub struct Packet<P> {
    trace_type: u8,
    time_tag: Option<u16>,
    hart: u64,
    payload: P,
}

impl<P> Packet<P> {
    /// Retrieve the [`TraceType`] of this packet's payload
    ///
    /// Returns [`None`] if the trace type is unknown.
    pub fn trace_type(&self) -> Option<TraceType> {
        self.raw_trace_type().try_into().ok()
    }

    /// Retrieve the raw trace type of this packet
    pub fn raw_trace_type(&self) -> u8 {
        self.trace_type
    }

    /// Retrieve this packet's partial time stamp if present
    pub fn time_tag(&self) -> Option<u16> {
        self.time_tag
    }

    /// Retrieve this packet's hart index
    ///
    /// The index specifies the address of the hart's trace unit within the
    /// messaging infrastructure. It may not be identical to the value of the
    /// `mhartid` CSR for that hart.
    pub fn hart(&self) -> u64 {
        self.hart
    }

    /// Retrieve the packet's payload
    pub fn payload(&self) -> &P {
        &self.payload
    }
}

impl<U: unit::Unit> Packet<decoder::Scoped<'_, '_, U>> {
    /// Decode the packet's E-Trace payload
    pub fn decode_payload(mut self) -> Result<payload::Payload<U::IOptions, U::DOptions>, Error> {
        let trace_type = self
            .raw_trace_type()
            .try_into()
            .map_err(Error::UnknownTraceType)?;
        match trace_type {
            TraceType::Instruction => {
                Decode::decode(self.payload.decoder_mut()).map(payload::Payload::InstructionTrace)
            }
            TraceType::Data => Ok(payload::Payload::DataTrace),
        }
    }
}

impl<'a, 'd, U> Decode<'a, 'd, U> for Packet<decoder::Scoped<'a, 'd, U>> {
    fn decode(decoder: &'a mut Decoder<'d, U>) -> Result<Self, Error> {
        let payload_len: usize = decoder.read_bits(5)?;
        let trace_type = decoder.read_bits::<u8>(2)?;
        let time_tag = decoder
            .read_bit()?
            .then(|| decoder.read_bits(16))
            .transpose()?;
        let hart = decoder.read_bits(decoder.hart_index_width())?;
        decoder.advance_to_byte();
        decoder::Scoped::new(decoder, payload_len).map(|payload| Self {
            trace_type,
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
    Data,
}

impl TryFrom<u8> for TraceType {
    type Error = u8;

    fn try_from(num: u8) -> Result<Self, Self::Error> {
        match num {
            0b10 => Ok(TraceType::Instruction),
            0b11 => Ok(TraceType::Data),
            unknown => Err(unknown),
        }
    }
}

impl PartialEq<u8> for TraceType {
    fn eq(&self, other: &u8) -> bool {
        Self::try_from(*other).map(|o| *self == o).unwrap_or(false)
    }
}

impl fmt::Display for TraceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Instruction => write!(f, "Instruction"),
            Self::Data => write!(f, "Data"),
        }
    }
}
