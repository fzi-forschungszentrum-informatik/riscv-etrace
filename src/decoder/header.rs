// Copyright (C) 2024 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

//! Implements the header and its decoding.
use super::{Decode, Decoder, Error};

/// Each packet has a header specifying at least the payload length, trace type,
/// whether a timestamp exists and the hart which produced the packet.
#[derive(Debug, Eq, PartialEq)]
pub struct Header {
    /// [Payload](crate::decoder::Payload) length in bytes.
    pub payload_len: usize,
    pub trace_type: TraceType,
    pub has_timestamp: bool,
    #[cfg(feature = "time_tag")]
    pub time_tag: Option<u16>,
    pub hart_index: usize,
}

impl Decode for Header {
    fn decode(decoder: &mut Decoder, slice: &[u8]) -> Result<Self, Error> {
        let payload_length = decoder.read(5, slice)?;
        let trace_type = TraceType::decode(decoder, slice)?;
        let has_timestamp = decoder.read_bit(slice)?;
        #[cfg(feature = "time_tag")]
        let time_tag = Some(decoder.read(16, slice)? as u16);
        let cpu_index = decoder.read(decoder.proto_conf.cpu_index_width, slice)?;
        if trace_type != TraceType::Instruction {
            return Err(Error::WrongTraceType(trace_type));
        }

        Ok(Header {
            payload_len: payload_length.try_into().unwrap(),
            trace_type,
            has_timestamp,
            #[cfg(feature = "time_tag")]
            time_tag,
            hart_index: cpu_index.try_into().unwrap(),
        })
    }
}

/// Defines which trace type a packet has. Currently only instruction tracing is supported.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TraceType {
    Instruction,
}

impl Decode for TraceType {
    fn decode(decoder: &mut Decoder, slice: &[u8]) -> Result<Self, Error> {
        match decoder.read(2, slice)? {
            0b10 => Ok(TraceType::Instruction),
            unknown => Err(Error::UnknownTraceType(unknown)),
        }
    }
}
