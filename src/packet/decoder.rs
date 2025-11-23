// Copyright (C) 2024, 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Packet decoder

use core::fmt;
use core::num::NonZeroUsize;
use core::ops;

use super::error::Error;
use super::payload::InstructionTrace;
use super::truncate::TruncateNum;
use super::unit::Unit;
use super::width::Widths;
use super::{encap, smi};

/// A decoder for individual packets and/or [payloads][super::payload]
///
/// Use this decoder to decode [`encap::Packet`]s or [`smi::Packet`]s.
///
/// A decoder is created via a [`Builder`][super::Builder]. From the supplied
/// data, packets of different formats may be decoded using the corresponding
/// fns such as [`decode_encap_packet`][Self::decode_encap_packet] or
/// [`decode_smi_packet`][Self::decode_smi_packet]. After assessing whether a
/// packet is relevant or not, its [`Payload`][super::payload::Payload] may be
/// decoded. Multiple packets from different harts may be sequentially decoded
/// by a single decoder instance.
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
/// incomplete packet. We do not need to clone the [`Builder`][super::Builder]
/// since it happens to be [`Copy`] in this case.
///
/// ```
/// use riscv_etrace::packet;
///
/// # let parameters = Default::default();
/// # let trace_data = b"\x45\x73\x0a\x00";
/// # let trace_data_next = b"\x45\x73\x0a\x00\x00\x20\x41\x01";
/// let builder = packet::builder().with_params(&parameters);
/// let mut decoder = builder.build(trace_data);
/// loop {
///     let packet = match decoder.decode_encap_packet() {
///         Ok(packet) => packet,
///         Err(packet::Error::InsufficientData(_)) => break,
///         Err(e) => panic!("{e:?}"),
///     };
///     // ...
/// }
/// let mut decoder = builder.build(trace_data_next);
/// loop {
///     let packet = match decoder.decode_encap_packet() {
///         Ok(packet) => packet,
///         Err(packet::Error::InsufficientData(_)) => break,
///         Err(e) => panic!("{e:?}"),
///     };
///     // ...
/// }
/// ```
#[derive(Clone)]
pub struct Decoder<'d, U> {
    data: &'d [u8],
    bit_pos: usize,
    field_widths: Widths,
    unit: U,
    hart_index_width: u8,
    timestamp_width: u8,
    trace_type_width: u8,
}

impl<'d, U> Decoder<'d, U> {
    /// Create a new decoder
    pub(super) fn new(
        field_widths: Widths,
        unit: U,
        hart_index_width: u8,
        timestamp_width: u8,
        trace_type_width: u8,
    ) -> Self {
        Self {
            data: &[],
            bit_pos: 0,
            field_widths,
            unit,
            hart_index_width,
            timestamp_width,
            trace_type_width,
        }
    }

    /// Retrieve the number of bytes left in this decoder's data
    ///
    /// If the decoder is currently not at a byte boundary, the number returned
    /// includes the partially decoded byte.
    pub fn bytes_left(&self) -> usize {
        self.data.len().saturating_sub(self.bit_pos >> 3)
    }

    /// Retrieve the current byte position
    ///
    /// Returns the zero-based position of the byte which is currently decoded.
    /// If the current bit position is on a byte boundary, the position of the
    /// byte after the boundary is returned.
    ///
    /// # Example
    ///
    /// ```
    /// use riscv_etrace::packet;
    ///
    /// # let trace_data = &[];
    /// let mut decoder = packet::builder().build(trace_data);
    /// assert_eq!(decoder.byte_pos(), 0);
    /// ```
    pub fn byte_pos(&self) -> usize {
        self.bit_pos >> 3
    }

    /// Reset the inner data to the given byte slice
    pub fn reset(&mut self, data: &'d [u8]) {
        self.bit_pos = 0;
        self.data = data;
    }

    /// Decode a single [`encap::Packet`]
    ///
    /// Decodes a single [`encap::Packet`], which will consume all associated
    /// data from the input when [dropped][Drop::drop], leaving the decoder at
    /// the byte boundary following the packet. If an error is returned, the
    /// decoder may be in an unspecified state.
    pub fn decode_encap_packet(&mut self) -> Result<encap::Packet<'_, 'd, U>, Error> {
        Decode::decode(self)
    }

    /// Decode a single [`smi::Packet`] consisting of header and payload
    ///
    /// Decodes a single [`smi::Packet`], consuming the associated data from the
    /// input. After successful operation, the decoder is left at the byte
    /// boundary following the packet, ready to decode the next one. A failure
    /// may leave the decoder in an unspecified state.
    pub fn decode_smi_packet(&mut self) -> Result<smi::Packet<'_, 'd, U>, Error> {
        Decode::decode(self)
    }

    /// Decode a single, stand-alone [`InstructionTrace`] payload
    ///
    /// Decodes a single [`InstructionTrace`] payload, consuming the associated
    /// data from the input and sign-extending the input if neccessary. After
    /// successful operation, the decoder is left at the _bit_ boundary
    /// following the payload. A failure may leave the decoder in an unspecified
    /// state.
    pub fn decode_payload(&mut self) -> Result<InstructionTrace<U::IOptions, U::DOptions>, Error>
    where
        U: Unit,
    {
        Decode::decode(self)
    }

    /// Retrieve this decoder's [`Unit`]
    pub fn unit(&self) -> &U {
        &self.unit
    }

    /// Retrieve the payload field widths
    pub(super) fn widths(&self) -> &Widths {
        &self.field_widths
    }

    /// Retrieve the hart index width
    pub(super) fn hart_index_width(&self) -> u8 {
        self.hart_index_width
    }

    /// Retrieve the width of the timestamp used in packet headers
    pub(super) fn timestamp_width(&self) -> u8 {
        self.timestamp_width
    }

    /// Retrieve the trace type width
    pub(super) fn trace_type_width(&self) -> u8 {
        self.trace_type_width
    }

    /// Advance the position to the next byte boundary
    pub(super) fn advance_to_byte(&mut self) {
        if self.bit_pos & 0x7 != 0 {
            self.bit_pos = (self.bit_pos & !0x7usize) + 8;
        }
    }

    /// Retrieve the remaining inner data, including the current byte
    pub(super) fn remaining_data(&self) -> &'d [u8] {
        self.data
            .split_at_checked(self.bit_pos >> 3)
            .unwrap_or_default()
            .1
    }

    /// Split the inner data at the given position
    ///
    /// On success, the inner data is set restricted to the half up to the given
    /// position, i.e. its length will be `mid`. The remaining data will be
    /// returned.
    pub(super) fn split_data(&mut self, mid: usize) -> Result<&'d [u8], Error> {
        if let Some((data, remaining)) = self.data.split_at_checked(mid) {
            self.data = data;
            Ok(remaining)
        } else {
            let need = mid
                .checked_sub(self.data.len())
                .and_then(NonZeroUsize::new)
                .unwrap_or(NonZeroUsize::MIN);
            Err(Error::InsufficientData(need))
        }
    }

    /// Read a single bit
    pub(super) fn read_bit(&mut self) -> Result<bool, Error> {
        let res = (self.get_byte(self.bit_pos >> 3)? >> (self.bit_pos & 0x07)) & 0x1;
        self.bit_pos += 1;
        Ok(res != 0)
    }

    /// Read a single differential bit
    ///
    /// The bit's value is considered to be [`true`] if it differs from the
    /// previous bit and [`false`] if it doesn't.
    pub(super) fn read_differential_bit(&mut self) -> Result<bool, Error> {
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
    pub(super) fn read_bits<T>(&mut self, bit_count: u8) -> Result<T, Error>
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

pub(super) trait Decode<'a, 'd, U>: Sized {
    fn decode(decoder: &'a mut Decoder<'d, U>) -> Result<Self, Error>;
}

/// Scoped decoder
///
/// This type wraps a mutable reference to a [`Decoder`]. The [`Decoder`] is
/// restricted to a predefined length and reset to the rest of the buffer after
/// the wrapper is dropped.
pub struct Scoped<'a, 'd, U> {
    decoder: &'a mut Decoder<'d, U>,
    remaining: &'d [u8],
}

impl<'a, 'd, U> Scoped<'a, 'd, U> {
    /// Create a new scoped decoder
    ///
    /// The given decoder is restricted to `length` past the current byte
    /// position and will be reset to the remaining data after the scoped
    /// decoder is dropped.
    pub fn new(decoder: &'a mut Decoder<'d, U>, length: usize) -> Result<Self, Error> {
        decoder
            .split_data(decoder.byte_pos().saturating_add(length))
            .map(|remaining| Self { decoder, remaining })
    }

    /// Retrieve the wrapped decoder
    pub fn decoder_mut(&mut self) -> &mut Decoder<'d, U> {
        self.decoder
    }
}

impl<U> fmt::Debug for Scoped<'_, '_, U> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Scoped")
            .field("unaligned_data", &self.decoder.remaining_data())
            .finish_non_exhaustive()
    }
}

impl<'a, 'd, U> Drop for Scoped<'a, 'd, U> {
    fn drop(&mut self) {
        self.decoder.reset(self.remaining);
    }
}
