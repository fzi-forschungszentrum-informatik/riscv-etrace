// Copyright (C) 2024, 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Packet decoder and entities it can decode (packets and payloads)
//!
//! This module provides definitions for [payloads][payload] and packets as well
//! as a [`Decoder`] for decoding them from raw trace data.

mod format;
pub mod payload;
pub mod smi;
pub mod sync;
pub mod truncate;
pub mod unit;
mod util;

#[cfg(test)]
mod tests;

use core::fmt;
use core::num::{NonZeroU8, NonZeroUsize};
use core::ops;

use crate::config;

use format::Format;
use truncate::TruncateNum;

/// Decoder errors
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Error {
    /// The trace type is not known to us
    UnknownTraceType(u8),
    /// The format/subformat is unknown.
    UnknownFmt(u8, Option<u8>),
    /// The branch format in [`payload::BranchCount`] is `0b01`.
    BadBranchFmt,
    /// Some more bytes of data are required for the operation to succeed
    InsufficientData(NonZeroUsize),
    /// The privilege level is not known. You might want to implement it.
    UnknownPrivilege(u8),
    /// Encountered an unknown encoder mode
    UnknownEncoderMode(u8),
}

impl core::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTraceType(t) => write!(f, "Unknown trace type {t}"),
            Self::UnknownFmt(t, None) => write!(f, "Unknown format {t}"),
            Self::UnknownFmt(t, Some(s)) => write!(f, "Unknown format,subformat {t},{s}"),
            Self::BadBranchFmt => write!(f, "Malformed branch format"),
            Self::InsufficientData(n) => write!(f, "At least {n} more bytes of data are required"),
            Self::UnknownPrivilege(p) => write!(f, "Unknown priviledge level {p}"),
            Self::UnknownEncoderMode(m) => write!(f, "Unknown encoder mode {m}"),
        }
    }
}

/// A decoder for individual packets and/or [`Payload`][payload::Payload]s
///
/// Use this decoder to decode individual [`smi::Packet`]s.
///
/// A decoder is created and loaded with raw data via a [`Builder`]. From that
/// data, the fn [`decode_smi_packet`][Self::decode_smi_packet] will decode one
/// [`smi::Packet`]s containing a [`Payload`][payload::Payload]. Multiple
/// packets from different harts may be sequentially decoded by a single decoder
/// instance.
///
/// If a packet could not be decoded due to insufficient data, the decoder will
/// report this by emitting an [`Error::InsufficientData`] error.
/// Alternatively, the number of bytes left in the input can be queried via the
/// fn [`bytes_left`][Self::bytes_left].
///
/// # Example
///
/// The follwing example demonstrates decoding of trace data in chunks with one
/// decoder per input, including the recovery from attempting to decode an
/// incomplete packet. We do not need to clone the [`Builder`] since it happens
/// to be [`Copy`] in this case.
///
/// ```
/// use riscv_etrace::decoder;
///
/// # let parameters = Default::default();
/// # let trace_data = b"\x45\x73\x0a\x00";
/// # let trace_data_next = b"\x45\x73\x0a\x00\x00\x20\x41\x01";
/// let builder = decoder::Builder::new()
///     .with_params(&parameters);
/// let mut decoder = builder.build(trace_data);
/// loop {
///     match decoder.decode_smi_packet() {
///         Ok(packet) => eprintln!("{packet:?}", ),
///         Err(decoder::Error::InsufficientData(_)) => break,
///         Err(e) => panic!("{e:?}"),
///     }
/// }
/// let mut decoder = builder.build(trace_data_next);
/// loop {
///     match decoder.decode_smi_packet() {
///         Ok(packet) => eprintln!("{packet:?}", ),
///         Err(decoder::Error::InsufficientData(_)) => break,
///         Err(e) => panic!("{e:?}"),
///     }
/// }
/// ```
#[derive(Clone)]
pub struct Decoder<'d, U> {
    data: &'d [u8],
    bit_pos: usize,
    field_widths: Widths,
    unit: U,
    hart_index_width: u8,
}

impl<U> Decoder<'_, U> {
    /// Retrieve the number of bytes left in this decoder's data
    pub fn bytes_left(&self) -> usize {
        self.data.len()
    }

    /// Decode a single [`smi::Packet`] consisting of header and payload
    ///
    /// Decodes a single [`smi::Packet`], consuming the associated data from the
    /// input. The returned packet's [`len`][`smi::Packet::len`] will contain
    /// the number of bytes consumed. After successful operation, the decoder is
    /// left at the byte boundary following the packet, ready to decode the next
    /// one. A failure may leave the decoder in an unspecified state.
    pub fn decode_smi_packet(&mut self) -> Result<smi::Packet<U::IOptions, U::DOptions>, Error>
    where
        U: unit::Unit,
    {
        let header = smi::Header::decode(self)?;
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
        let payload = self.decode_payload()?;

        self.bit_pos = 0;
        self.data = remaining;

        Ok(smi::Packet {
            header,
            payload,
            len,
        })
    }

    /// Decode a single, stand-alone [`Payload`][payload::Payload]
    ///
    /// Decodes a single [`Payload`][payload::Payload], consuming the associated
    /// data from the input and sign-extending the input if neccessary. After
    /// successful operation, the decoder is left at the _bit_ boundary
    /// following the payload. A failure may leave the decoder in an unspecified
    /// state.
    pub fn decode_payload(&mut self) -> Result<payload::Payload<U::IOptions, U::DOptions>, Error>
    where
        U: unit::Unit,
    {
        Format::decode(self)?.decode_payload(self)
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
    /// The bit's value is considered to be [`true`] if it differs from the
    /// previous bit and [`false`] if it doesn't.
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

/// Create a new [`Builder`] for [`Decoder`]s
pub fn builder() -> Builder<unit::Reference> {
    Default::default()
}

/// Biulder for [`Decoder`]s
///
/// A builder will build a single decoder for a specific slice of bytes. If the
/// trace data is read in chunks, it may thus be neccessary to build
/// [`Decoder`]s repeatedly. For this purpose, [`Builder`] implements [`Copy`]
/// and [`Clone`] as long as the [`Unit`][unit::Unit] used does.
#[derive(Copy, Clone, Default)]
pub struct Builder<U = unit::Reference> {
    field_widths: Widths,
    unit: U,
    hart_index_width: u8,
}

impl Builder<unit::Reference> {
    /// Create a new builder
    pub fn new() -> Self {
        Default::default()
    }
}

impl<U> Builder<U> {
    /// Set the [`config::Parameters`] of the [`Decoder`] built
    pub fn with_params(self, params: &config::Parameters) -> Self {
        Self {
            field_widths: params.into(),
            ..self
        }
    }

    /// Set the trace [`Unit`][unit::Unit] implementation for the [`Decoder`]
    pub fn for_unit<V>(self, unit: V) -> Builder<V> {
        Builder {
            field_widths: self.field_widths,
            unit,
            hart_index_width: self.hart_index_width,
        }
    }

    /// Set the width to use for CPU index fields
    pub fn with_hart_index_width(self, hart_index_width: u8) -> Self {
        Self {
            hart_index_width,
            ..self
        }
    }

    /// Build a [`Decoder`] for the given data
    pub fn build(self, data: &[u8]) -> Decoder<U> {
        Decoder {
            data,
            bit_pos: 0,
            field_widths: self.field_widths,
            unit: self.unit,
            hart_index_width: self.hart_index_width,
        }
    }
}

trait Decode<U>: Sized {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error>;
}

/// Widths of various payload fields
#[derive(Copy, Clone)]
struct Widths {
    pub cache_index: u8,
    pub context: Option<NonZeroU8>,
    pub time: Option<NonZeroU8>,
    pub ecause: NonZeroU8,
    pub format0_subformat: u8,
    pub iaddress_lsb: NonZeroU8,
    pub iaddress: NonZeroU8,
    pub privilege: NonZeroU8,
    pub stack_depth: Option<NonZeroU8>,
}

impl Default for Widths {
    fn default() -> Self {
        (&config::Parameters::default()).into()
    }
}

impl From<&config::Parameters> for Widths {
    fn from(params: &config::Parameters) -> Self {
        let stack_depth = params.return_stack_size_p
            + params.call_counter_size_p
            + if params.return_stack_size_p > 0 { 1 } else { 0 };
        Self {
            cache_index: params.cache_size_p,
            context: (!params.nocontext_p).then_some(params.context_width_p),
            time: (!params.notime_p).then_some(params.time_width_p),
            ecause: params.ecause_width_p,
            format0_subformat: params.f0s_width_p,
            iaddress_lsb: params.iaddress_lsb_p,
            iaddress: params.iaddress_width_p,
            privilege: params.privilege_width_p,
            stack_depth: NonZeroU8::new(stack_depth),
        }
    }
}
