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
/// SMI-independent [`InstructionTrace`][payload::InstructionTrace] payload.
#[derive(Debug)]
pub struct Packet<I, D> {
    time_tag: Option<u16>,
    hart: u64,
    payload: payload::InstructionTrace<I, D>,
}

impl<I, D> Packet<I, D> {
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

    /// Retrieve the packet's ETrace payload
    pub fn payload(self) -> Result<payload::Payload<I, D>, Error> {
        Ok(self.payload.into())
    }
}

impl<U: unit::Unit> Decode<'_, '_, U> for Packet<U::IOptions, U::DOptions> {
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

impl TryFrom<u8> for TraceType {
    type Error = u8;

    fn try_from(num: u8) -> Result<Self, Self::Error> {
        match num {
            0b10 => Ok(TraceType::Instruction),
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
        }
    }
}

impl<U> Decode<'_, '_, U> for TraceType {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        match decoder.read_bits::<u8>(2)? {
            0b10 => Ok(TraceType::Instruction),
            unknown => Err(Error::UnknownTraceType(unknown)),
        }
    }
}
