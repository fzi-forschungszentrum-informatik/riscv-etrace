// Copyright (C) 2024, 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Packet encoder

use core::num::NonZeroUsize;
use core::ops;

use super::error::Error;
use super::truncate::TruncateNum;
use super::width::Widths;

/// Am encoder for packets and/or [payloads][super::payload]
pub struct Encoder<'d, U> {
    data: &'d mut [u8],
    bit_pos: usize,
    bytes_committed: usize,
    field_widths: Widths,
    unit: U,
    hart_index_width: u8,
    timestamp_width: u8,
    trace_type_width: u8,
    compress: bool,
}

impl<'d, U> Encoder<'d, U> {
    /// Create a new encoder
    pub(super) fn new(
        data: &'d mut [u8],
        field_widths: Widths,
        unit: U,
        hart_index_width: u8,
        timestamp_width: u8,
        trace_type_width: u8,
        compress: bool,
    ) -> Self {
        Self {
            data,
            bit_pos: 0,
            bytes_committed: 0,
            field_widths,
            unit,
            hart_index_width,
            timestamp_width,
            trace_type_width,
            compress,
        }
    }

    /// Reset the inner data to the given byte slice
    pub fn reset(&mut self, data: &'d mut [u8]) {
        self.data = data;
        self.bit_pos = 0;
        self.bytes_committed = 0;
    }

    /// Retrieve the number of bytes in the buffer that are not committed
    pub fn uncommitted(&self) -> usize {
        self.data.len() - self.bytes_committed
    }

    /// Encode one entity
    pub fn encode(&mut self, data: &impl Encode<'d, U>) -> Result<(), Error> {
        data.encode(self)
    }

    /// Finish the encoding process
    pub fn finish(self) -> (&'d mut [u8], usize) {
        let len = if self.bit_pos == 0 {
            0
        } else {
            self.bytes_committed
        };
        (self.data, len)
    }

    /// Retrieve this encoder's unit
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

    /// Extract a mutable chunk from the beginning of the uncommitted region
    ///
    /// Returns a chunk of fixed size from the beginning of the uncommitted
    /// region and resets the encoder to the remaining buffer after that chunk
    /// on success. On failure, the encoder is left with an empty buffer.
    pub(super) fn first_uncommitted_chunk<const N: usize>(
        &mut self,
    ) -> Result<&'d mut [u8; N], Error> {
        let (chunk, data) = core::mem::take(&mut self.data)
            .split_at_mut_checked(self.bytes_committed)
            .and_then(|(_, d)| d.split_first_chunk_mut())
            .ok_or_else(|| {
                self.reset(&mut []);
                Error::BufferTooSmall
            })?;
        self.reset(data);
        Ok(chunk)
    }

    /// Write a single bit
    pub(super) fn write_bit(&mut self, bit: bool) -> Result<(), Error> {
        let byte_pos = self.bit_pos >> 3;
        let byte = self.get_byte(byte_pos)?;
        let mask = 0xff << (self.bit_pos & 0x7);
        let byte = if bit { byte | mask } else { byte & !mask };
        self.write_byte(byte, byte_pos)?;
        self.bit_pos += 1;
        Ok(())
    }

    /// Write a single differential bit
    ///
    /// If [`true`], a negation of the current last bit will be written.
    pub(super) fn write_differential_bit(&mut self, bit: bool) -> Result<(), Error> {
        let byte_pos = self.bit_pos >> 3;
        let mut byte = self.get_byte(byte_pos)?;
        if bit {
            byte ^= 0xff << (self.bit_pos & 0x7);
        }
        self.write_byte(byte, byte_pos)?;
        self.bit_pos += 1;
        Ok(())
    }

    /// Write an integer field
    ///
    /// # Safety
    ///
    /// May panic if `bit_count` is higher then the bit width of the target
    /// integer.
    pub(super) fn write_bits<T>(&mut self, bits: T, bit_count: u8) -> Result<(), Error>
    where
        T: Copy
            + ops::Shl<usize, Output = T>
            + ops::Shr<usize, Output = T>
            + ops::BitOrAssign<T>
            + TruncateNum,
    {
        let Some(bit_count) = NonZeroUsize::new(bit_count.into()) else {
            return Ok(());
        };

        let bit_pos = self.bit_pos & 0x07;
        let mut byte_pos = self.bit_pos >> 3;

        let mut byte = self.get_byte(byte_pos)?;
        byte &= (1 << bit_pos) - 1;
        byte |= bits.lsb() << bit_pos;

        let mut bits_written = 8 - bit_pos;
        while bits_written < bit_count.get() {
            self.write_byte(byte, byte_pos)?;
            byte_pos += 1;
            byte = (bits >> bits_written).lsb();
            bits_written += 8;
        }

        if let Some(upper) = NonZeroUsize::new(bits_written - bit_count.get()) {
            let mask = !(0xff >> upper.get());
            if (bits >> (bit_count.get() - 1)).lsb() & 1 != 0 {
                byte |= mask;
            } else {
                byte &= !mask;
            }
        }

        self.write_byte(byte, byte_pos)?;
        self.bit_pos += bit_count.get();
        Ok(())
    }

    /// Get the byte at the given byte position
    ///
    /// If the position is past the boundary of committed bytes, the result of
    /// expanding the committed sequence will be returned.
    fn get_byte(&mut self, byte_pos: usize) -> Result<u8, Error> {
        if byte_pos < self.bytes_committed {
            return self
                .data
                .get(byte_pos)
                .copied()
                .ok_or(Error::BufferTooSmall);
        }

        let last_committed = self.bytes_committed.saturating_sub(1);
        let last_committed = self.data.get(last_committed).ok_or(Error::BufferTooSmall)?;
        if last_committed & 0x80 != 0 {
            Ok(0xff)
        } else {
            Ok(0x00)
        }
    }

    /// Write a byte at the specified byte position
    ///
    /// The committed bytes will be expanded if necessary.
    fn write_byte(&mut self, byte: u8, byte_pos: usize) -> Result<(), Error> {
        let data: &mut [u8] = self.data;
        let split = data
            .split_at_mut_checked(byte_pos)
            .map(|(d, t)| (d, t.first_mut()));
        let (data, target) = if let Some(split) = split {
            split
        } else {
            (data, None)
        };

        if let Some((extend, fill)) = data
            .split_at_mut_checked(self.bytes_committed)
            .and_then(|(c, f)| c.last().map(|e| (e & 0x80 != 0, f)))
        {
            if self.compress && matches!((byte, extend), (0x00, false) | (0xff, true)) {
                return Ok(());
            }
            fill.fill(if extend { 0xff } else { 0x00 });
        }

        *target.ok_or(Error::BufferTooSmall)? = byte;
        self.bytes_committed = byte_pos + 1;
        Ok(())
    }
}

/// Encodable item
///
/// Items implementing this trait may be encoded using an [`Encoder`].
pub trait Encode<'d, U>: Sized {
    /// Encode this item
    fn encode(&self, encoder: &mut Encoder<'d, U>) -> Result<(), Error>;
}
