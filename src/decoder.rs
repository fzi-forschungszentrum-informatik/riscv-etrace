// Copyright (C) 2024 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

//! Implements the packet decoder.
use core::fmt;

use crate::decoder::format::Format;
use crate::decoder::header::*;
use crate::decoder::payload::*;
use crate::{ProtocolConfiguration};

mod format;
pub mod header;
pub mod payload;

#[cfg(test)]
mod tests;

use Error::ReadTooLong;

/// Defines the decoder specific configuration. Used only by the [decoder](self).
#[derive(Copy, Clone, Debug)]
pub struct DecoderConfiguration {
    pub decompress: bool,
}

impl Default for DecoderConfiguration {
    fn default() -> Self {
        DecoderConfiguration { decompress: true }
    }
}

/// A list of possible errors during decoding of a single packet.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Error {
    /// [TraceType] does not indicate an instruction trace. The unknown trace type is returned.
    UnknownTraceType(u64),
    WrongTraceType(TraceType),
    /// The branch format in [BranchCount] is `0b01`.
    BadBranchFmt,
    /// The packet cannot be parsed because the next read of bits would be outside the packet buffer
    /// or too many bits (> 64) were requested.
    ReadTooLong {
        bit_pos: usize,
        bit_count: usize,
        buffer_size: usize,
    },
    /// The privilege level is not known. You might want to implement it.
    UnknownPrivilege(u8),
}

impl core::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTraceType(t) => write!(f, "Unknown trace type {t}"),
            Self::WrongTraceType(t) => write!(f, "Unexpected trace type {t}"),
            Self::BadBranchFmt => write!(f, "Malformed branch format"),
            Self::ReadTooLong {
                bit_pos,
                bit_count,
                buffer_size,
            } => write!(
                f,
                "Read if {bit_count} bits from {bit_pos} exceds buffer of size {buffer_size}",
            ),
            Self::UnknownPrivilege(p) => write!(f, "Unknown priviledge level {p}"),
        }
    }
}

/// The maximum length a payload can have decompressed. Found by changing this value until the
/// decoder no longer crashed on a real trace and adding 2.
pub const PAYLOAD_MAX_DECOMPRESSED_LEN: usize = 20;

/// A decoder for packets. The decoder is stateless in respect to a single packet parse.
/// Multiple packets from different harts may be sequentially parsed by a single decoder
/// instance as the decoder is stateless between [decode()](Decoder::decode_packet()) calls.
#[derive(Clone)]
pub struct Decoder<'d> {
    data: &'d [u8],
    bit_pos: usize,
    proto_conf: ProtocolConfiguration,
    decoder_conf: DecoderConfiguration,
}

impl Default for Decoder<'static> {
    fn default() -> Self {
        Decoder::new(ProtocolConfiguration::default(), DecoderConfiguration::default())
    }
}

impl<'d> Decoder<'d> {
    pub fn new(proto_conf: ProtocolConfiguration, decoder_conf: DecoderConfiguration) -> Self {
        Decoder {
            data: &[],
            bit_pos: 0,
            proto_conf,
            decoder_conf,
        }
    }

    /// Set the data being decoded
    pub fn with_data(self, data: &[u8]) -> Decoder<'_> {
        Decoder {
            data,
            bit_pos: 0,
            ..self
        }
    }

    fn reset(&mut self) {
        self.bit_pos = 0;
    }

    fn read_bit(&mut self, slice: &[u8]) -> Result<bool, Error> {
        if self.bit_pos >= slice.len() * 8 {
            return Err(ReadTooLong {
                buffer_size: slice.len() * 8,
                bit_count: 1,
                bit_pos: self.bit_pos,
            });
        }
        let byte_pos = self.bit_pos / 8;
        let mut value = slice[byte_pos];
        value >>= self.bit_pos % 8;
        self.bit_pos += 1;
        Ok((value & 1_u8) == 0x01)
    }

    fn read(&mut self, bit_count: usize, slice: &[u8]) -> Result<u64, Error> {
        if bit_count == 0 {
            return Ok(0);
        }
        if bit_count > 64 {
            return Err(ReadTooLong {
                buffer_size: slice.len() * 8,
                bit_count,
                bit_pos: self.bit_pos,
            });
        }
        if bit_count + self.bit_pos > slice.len() * 8 {
            return Err(ReadTooLong {
                buffer_size: slice.len() * 8,
                bit_count,
                bit_pos: self.bit_pos,
            });
        }
        let byte_pos = self.bit_pos / 8;
        let mut value = u64::from_le_bytes(slice[byte_pos..byte_pos + 8].try_into().unwrap());
        // Ignore first 'self.bit_pos' LSBs in first byte as they are already consumed.
        value >>= self.bit_pos % 8;
        // Zero out everything except 'bit_count' LSBs if bit_count != 64.
        if bit_count < 64 {
            value &= (1_u64 << bit_count) - 1;
        }
        self.bit_pos += bit_count;
        // Check if we need to read into the 9th byte because of an unaligned read
        if self.bit_pos > ((byte_pos + 8) * 8) {
            let missing_bit_count = (self.bit_pos - ((byte_pos + 8) * 8)) % 8;
            // Take 9th byte and mask MSBs that will not be read
            let missing_msbs = slice[byte_pos + 8] & u8::MAX >> (8 - missing_bit_count);
            // Shift MSBs into correct position in u64 and add with previously read value
            let msbs_u64 = (missing_msbs as u64) << (bit_count - missing_bit_count);
            Ok(value + msbs_u64)
        } else {
            Ok(value)
        }
    }

    /// Decodes a single packet consisting of header and payload from a continuous slice of memory.
    /// Returns immediately after parsing one packet and returns how many bits were read.
    /// Further bytes are ignored.
    pub fn decode_packet(&mut self, slice: &[u8]) -> Result<Packet, Error> {
        self.reset();
        let header = Header::decode(self, slice)?;
        // Set the bit position to the beginning of the start of the next byte for payload decoding
        // if not at the first bit of the first payload byte.
        if self.bit_pos % 8 != 0 {
            self.bit_pos += 8 - (self.bit_pos % 8);
        }
        let payload_start = self.bit_pos / 8;
        let len = payload_start + header.payload_len;

        if self.decoder_conf.decompress {
            debug_assert!(header.payload_len <= PAYLOAD_MAX_DECOMPRESSED_LEN);
            let mut sign_expanded = if slice[payload_start + header.payload_len - 1] & 0x80 == 0 {
                [0; PAYLOAD_MAX_DECOMPRESSED_LEN]
            } else {
                [0xFF; PAYLOAD_MAX_DECOMPRESSED_LEN]
            };
            sign_expanded[0..header.payload_len]
                .copy_from_slice(&slice[payload_start..header.payload_len + payload_start]);
            self.reset();
            let payload =
                Format::decode(self, &sign_expanded)?.decode_payload(self, &sign_expanded)?;
            Ok(Packet {
                header,
                payload,
                len,
            })
        } else {
            let payload = Format::decode(self, slice)?.decode_payload(self, slice)?;
            Ok(Packet {
                header,
                payload,
                len,
            })
        }
    }
}

trait Decode: Sized {
    fn decode(decoder: &mut Decoder, slice: &[u8]) -> Result<Self, Error>;
}

/// A single protocol packet emitted by the encoder.
/// Each packet consists of a single header and a payload.
#[derive(Debug)]
pub struct Packet {
    pub header: Header,
    pub payload: Payload,
    /// Length of the packet in bytes.
    pub len: usize,
}
