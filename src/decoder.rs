// Copyright (C) 2024 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

//! Implements the packet decoder.
use core::fmt;
use core::num::NonZeroUsize;
use core::ops;

use crate::decoder::format::Format;
use crate::decoder::header::*;
use crate::decoder::payload::*;
use crate::{ProtocolConfiguration};

mod format;
pub mod header;
pub mod payload;
pub mod truncate;

#[cfg(test)]
mod tests;

use truncate::TruncateNum;
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
    /// Some more bytes of data are required for the operation to succeed
    InsufficientData(NonZeroUsize),
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
            Self::InsufficientData(n) => write!(f, "At least {n} more bytes of data are required"),
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

    /// Decodes a single packet consisting of header and payload from a continuous slice of memory.
    /// Returns immediately after parsing one packet and returns how many bits were read.
    /// Further bytes are ignored.
    pub fn decode_packet(&mut self, slice: &'d [u8]) -> Result<Packet, Error> {
        *self = self.clone().with_data(slice);
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
            let mut decoder = self.clone().with_data(&sign_expanded);
            let payload = Format::decode(&mut decoder, &sign_expanded)?
                .decode_payload(self, &sign_expanded)?;
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

    /// Read a single bit
    fn read_bit(&mut self) -> Result<bool, Error> {
        let res = (self.get_byte(self.bit_pos >> 3)? >> (self.bit_pos & 0x07)) & 0x1;
        self.bit_pos += 1;
        Ok(res != 0)
    }

    /// Read a number of bits as an integer
    ///
    /// Unsigned integers will be left-padded with zeroes, signed integers will
    /// be sign-extended.
    ///
    /// # Safety
    ///
    /// May panic if `bit_count` is higher then the bit width of the target
    /// integer.
    fn read_bits<T>(&mut self, bit_count: u8) -> Result<T, Error>
    where
        T: From<u8>
            + ops::Shl<usize, Output = T>
            + ops::Shr<usize, Output = T>
            + ops::BitOrAssign<T>
            + TruncateNum,
    {
        let lowest_bits = self.bit_pos & 0x07;
        let mut byte_pos = self.bit_pos >> 3;
        let mut res = T::from(self.get_byte(byte_pos)?) >> lowest_bits;
        let mut bits_extracted = 8 - lowest_bits;

        while bits_extracted < bit_count.into() {
            byte_pos += 1;
            res |= T::from(self.get_byte(byte_pos)?) << bits_extracted;
            bits_extracted += 8;
        }

        self.bit_pos += usize::from(bit_count);
        Ok(res.truncated(bit_count))
    }

    /// Get the byte at the given byte position
    ///
    /// If the byte position is past the end of the current data source, the
    /// result of a decompression if returned.
    fn get_byte(&self, pos: usize) -> Result<u8, Error> {
        if let Some(byte) = self.data.get(pos) {
            Ok(*byte)
        } else {
            self.data
                .last()
                .map(|b| if b & 0x80 != 0 { 0xFF } else { 0x00 })
                .ok_or(Error::InsufficientData(NonZeroUsize::MIN))
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
