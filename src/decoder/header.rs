// Copyright (C) 2024 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Implements the header and its decoding.

use core::fmt;

use super::{Decode, Decoder, Error};

/// Each packet has a header specifying at least the payload length, trace type,
/// whether a timestamp exists and the hart which produced the packet.
#[derive(Debug, Eq, PartialEq)]
pub struct Header {
    /// [Payload](crate::decoder::Payload) length in bytes.
    pub payload_len: usize,
    pub trace_type: TraceType,
    pub time_tag: Option<u16>,
    pub hart_index: usize,
}

impl Decode for Header {
    fn decode(decoder: &mut Decoder) -> Result<Self, Error> {
        let payload_len = decoder.read_bits(5)?;
        let trace_type = TraceType::decode(decoder)?;
        let time_tag = decoder
            .read_bit()?
            .then(|| decoder.read_bits(16))
            .transpose()?;
        let hart_index = decoder.read_bits(decoder.proto_conf.cpu_index_width)?;
        if trace_type != TraceType::Instruction {
            return Err(Error::WrongTraceType(trace_type));
        }

        Ok(Header {
            payload_len,
            trace_type,
            time_tag,
            hart_index,
        })
    }
}

/// Defines which trace type a packet has. Currently only instruction tracing is supported.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TraceType {
    Instruction,
}

impl fmt::Display for TraceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Instruction => write!(f, "Instruction"),
        }
    }
}

impl Decode for TraceType {
    fn decode(decoder: &mut Decoder) -> Result<Self, Error> {
        match decoder.read_bits::<u8>(2)? {
            0b10 => Ok(TraceType::Instruction),
            unknown => Err(Error::UnknownTraceType(unknown)),
        }
    }
}
