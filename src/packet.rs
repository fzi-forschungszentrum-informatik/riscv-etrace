// Copyright (C) 2024, 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Packet decoder and entities it can decode (packets and payloads)
//!
//! This module provides definitions for [payloads][payload] and packets as well
//! as a [`decoder`] for decoding them from raw trace data.

pub mod decoder;
pub mod encap;
pub mod encoder;
pub mod error;
pub mod payload;
pub mod smi;
pub mod sync;
pub mod truncate;
pub mod unit;
mod util;
mod width;

#[cfg(test)]
mod tests;

pub use error::Error;

use crate::config;

/// Create a new [`Builder`] for [`Decoder`][decoder::Decoder]s
pub fn builder() -> Builder<unit::Reference> {
    Default::default()
}

/// Builder for [`Decoder`][decoder::Decoder]s
///
/// A builder will build a single decoder for a specific slice of bytes. If the
/// trace data is read in chunks, it may thus be neccessary to build
/// [`Decoder`][decoder::Decoder]s repeatedly. For this purpose, [`Builder`]
/// implements [`Copy`] and [`Clone`] as long as the [`Unit`][unit::Unit] used
/// does.
#[derive(Copy, Clone, Default)]
pub struct Builder<U = unit::Reference> {
    field_widths: width::Widths,
    unit: U,
    hart_index_width: u8,
    timestamp_width: u8,
    trace_type_width: u8,
    no_compress: bool,
}

impl Builder<unit::Reference> {
    /// Create a new builder
    pub fn new() -> Self {
        Default::default()
    }
}

impl<U> Builder<U> {
    /// Set the [`config::Parameters`]
    pub fn with_params(self, params: &config::Parameters) -> Self {
        Self {
            field_widths: params.into(),
            ..self
        }
    }

    /// Set the trace [`Unit`][unit::Unit] implementation
    pub fn for_unit<V>(self, unit: V) -> Builder<V> {
        Builder {
            field_widths: self.field_widths,
            unit,
            hart_index_width: self.hart_index_width,
            timestamp_width: self.timestamp_width,
            trace_type_width: self.trace_type_width,
            no_compress: self.no_compress,
        }
    }

    /// Set the width to use for packet source index fields
    ///
    /// Set the width of fields containing source indices in applicable types of
    /// packets.
    pub fn with_hart_index_width(self, hart_index_width: u8) -> Self {
        Self {
            hart_index_width,
            ..self
        }
    }

    /// Set the width to use for packet timestamps
    ///
    /// Set the width of timestamps in applicable types of encapsulations, e.g.
    /// packet headers. This does not affect the width of the `time` field in
    /// context payloads.
    ///
    /// # Note
    ///
    /// For [`encap::Packet`]/[`encap::Normal`], this value denotes the field
    /// width in bytes rather than in bits.
    pub fn with_timestamp_width(self, timestamp_width: u8) -> Self {
        Self {
            timestamp_width,
            ..self
        }
    }

    /// Set the width to use for the trace type
    ///
    /// Set the width of fields identifying the trace type (e.g. "instruction"
    /// or "data") in applicable types of packets.
    pub fn with_trace_type_width(self, trace_type_width: u8) -> Self {
        Self {
            trace_type_width,
            ..self
        }
    }

    /// Activate or deactivate compression for [`Enocder`][encoder::Encoder]s
    ///
    /// Set whether or not [`Enocder`][encoder::Encoder]s build by this builder
    /// are configured to transparently compress data. Compression is activated
    /// by default.
    pub fn with_compression(self, compress: bool) -> Self {
        Self {
            no_compress: !compress,
            ..self
        }
    }

    /// Build a [`Decoder`][decoder::Decoder] for the given data
    pub fn decoder(self, data: &[u8]) -> decoder::Decoder<'_, U> {
        let mut res = decoder::Decoder::new(
            self.field_widths,
            self.unit,
            self.hart_index_width,
            self.timestamp_width,
            self.trace_type_width,
        );
        res.reset(data);
        res
    }

    /// Build an [`Encoder`][encoder::Encoder] for this configuration
    pub fn encoder(self, buffer: &mut [u8]) -> encoder::Encoder<'_, U> {
        encoder::Encoder::new(
            buffer,
            self.field_widths,
            self.unit,
            self.hart_index_width,
            self.timestamp_width,
            self.trace_type_width,
            !self.no_compress,
        )
    }
}
