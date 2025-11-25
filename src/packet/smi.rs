// Copyright (C) 2024, 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Siemens Messaging Infrastructure packet header

use core::fmt;

use super::decoder::{self, Decode, Decoder};
use super::encoder::{Encode, Encoder};
use super::{payload, unit, Error};

/// A Siemens Messaging Infrastructure (SMI) Packet
///
/// This type represents a decoded Siemens Messaging Infrastructure (SMI) Packet
/// as described in Chapter 7. Instruction Trace Encoder Output Packets of the
/// specification. A packet consists of SMI specific header information, and an
/// SMI-independent [`InstructionTrace`][payload::InstructionTrace] payload.
#[derive(Clone, Debug, PartialEq)]
pub struct Packet<P> {
    trace_type: u8,
    time_tag: Option<u16>,
    hart: u64,
    payload: P,
}

impl<P> Packet<P> {
    /// Create a new SMI packet
    pub fn new(trace_type: u8, hart: u64, payload: P) -> Self {
        Self {
            trace_type,
            time_tag: None,
            hart,
            payload,
        }
    }

    /// Attach a time tag to this packet
    pub fn with_time_tag(self, time_tag: u16) -> Self {
        Self {
            time_tag: time_tag.into(),
            ..self
        }
    }

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

impl<'d, U, P: Encode<'d, U>> Encode<'d, U> for Packet<P> {
    fn encode(&self, encoder: &mut Encoder<'d, U>) -> Result<(), Error> {
        let head = &mut encoder.first_uncommitted_chunk::<1>()?[0];
        if let Some(time_tag) = self.time_tag() {
            *encoder.first_uncommitted_chunk()? = time_tag.to_le_bytes();
        }
        let original_uncommitted = encoder.uncommitted();
        encoder.encode(&self.payload)?;

        let len = original_uncommitted - encoder.uncommitted();
        let len: u8 = len
            .try_into()
            .ok()
            .filter(|l| *l < 32)
            .ok_or(Error::PayloadTooBig(len))?;
        let trace_type = (self.trace_type & 0x3) << 5;
        let time_tag = if self.time_tag.is_some() { 0x80 } else { 0 };
        *head = len | trace_type | time_tag;
        Ok(())
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

impl From<TraceType> for u8 {
    fn from(t: TraceType) -> Self {
        match t {
            TraceType::Instruction => 0b10,
            TraceType::Data => 0b11,
        }
    }
}

impl PartialEq<u8> for TraceType {
    fn eq(&self, other: &u8) -> bool {
        u8::from(*self) == *other
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
