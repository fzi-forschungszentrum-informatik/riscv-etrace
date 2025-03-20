// Copyright (C) 2024 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Implements the packet decoder.

pub mod branch;
mod format;
pub mod header;
pub mod payload;
pub mod truncate;

use core::fmt;
use core::num::NonZeroUsize;
use core::ops;

use crate::ProtocolConfiguration;

use format::Format;
use header::Header;
use payload::Payload;

#[cfg(test)]
mod tests;

use truncate::TruncateNum;

/// A list of possible errors during decoding of a single packet.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Error {
    /// The trace type is not known to us
    UnknownTraceType(u64),
    WrongTraceType(header::TraceType),
    /// The branch format in [payload::BranchCount] is `0b01`.
    BadBranchFmt,
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
            Self::InsufficientData(n) => write!(f, "At least {n} more bytes of data are required"),
            Self::UnknownPrivilege(p) => write!(f, "Unknown priviledge level {p}"),
        }
    }
}

/// A decoder for packets. The decoder is stateless in respect to a single packet parse.
/// Multiple packets from different harts may be sequentially parsed by a single decoder
/// instance as the decoder is stateless between [decode()](Decoder::decode_packet()) calls.
#[derive(Clone)]
pub struct Decoder<'d> {
    data: &'d [u8],
    bit_pos: usize,
    proto_conf: ProtocolConfiguration,
}

impl Default for Decoder<'static> {
    fn default() -> Self {
        Decoder::new(ProtocolConfiguration::default())
    }
}

impl Decoder<'_> {
    pub fn new(proto_conf: ProtocolConfiguration) -> Self {
        Decoder {
            data: &[],
            bit_pos: 0,
            proto_conf,
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

    /// Decode a single [Packet] consisting of header and payload
    ///
    /// Decodes a single [Packet], consuming the associated data from the input.
    /// The returned packet's [Packet::len] will contain the number of bytes
    /// consumed. After successful operation, the decoder is left at the byte
    /// boundary following the packet, ready to decode the next one. A failure
    /// may leave the decoder in an unspecified state, requireing a reset via
    /// a call to [Self::with_data].
    pub fn decode_packet(&mut self) -> Result<Packet, Error> {
        let header = Header::decode(self)?;
        self.advance_to_byte();
        let payload_start = self.bit_pos >> 3;
        let len = payload_start + header.payload_len;

        let (payload, remaining) = self.data.split_at_checked(len).ok_or_else(|| {
            let need = len
                .checked_sub(self.data.len())
                .and_then(NonZeroUsize::new)
                .unwrap_or(NonZeroUsize::MIN);
            Error::InsufficientData(need)
        })?;
        self.data = payload;
        let payload = Format::decode(self)?.decode_payload(self)?;

        self.bit_pos = 0;
        self.data = remaining;

        Ok(Packet {
            header,
            payload,
            len,
        })
    }

    /// Advance the position to the next byte boundary
    fn advance_to_byte(&mut self) {
        if self.bit_pos & 0x7 != 0 {
            self.bit_pos = (self.bit_pos & !0x7usize) + 8;
        }
    }

    /// Read a single bit
    fn read_bit(&mut self) -> Result<bool, Error> {
        let res = (self.get_byte(self.bit_pos >> 3)? >> (self.bit_pos & 0x07)) & 0x1;
        self.bit_pos += 1;
        Ok(res != 0)
    }

    /// Read a single differential bit
    ///
    /// The bit's value is considered to be `true` if it differs from the
    /// previous bit and `false` if it doesn't.
    fn read_differential_bit(&mut self) -> Result<bool, Error> {
        let reference_pos = self
            .bit_pos
            .checked_sub(1)
            .ok_or(Error::InsufficientData(NonZeroUsize::MIN))?;
        let reference_bit = (self.get_byte(reference_pos >> 3)? >> (reference_pos & 0x07)) & 0x1;
        let raw_bit = (self.get_byte(self.bit_pos >> 3)? >> (self.bit_pos & 0x07)) & 0x1;
        self.bit_pos += 1;
        Ok(reference_bit ^ raw_bit != 0)
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
    fn decode(decoder: &mut Decoder) -> Result<Self, Error>;
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
