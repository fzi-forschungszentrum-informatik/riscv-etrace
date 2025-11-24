// Copyright (C) 2024, 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Types and utilities for the RISC-V Encapsulation specification
//!
//! This module provides types and utilities for processing packets following
//! the [Unformatted Trace & Diagnostic Data Packet Encapsulation for
//! RISC-V][encap] specification.
//!
//! [encap]: <https://github.com/riscv-non-isa/e-trace-encap/>

use super::decoder::{self, Decode, Decoder};
use super::{payload, unit, Error};

/// RISC-V Packet Encapsulation
///
/// This datatype represents a "Packet Encapsulation" as describes in Chapter 2
/// of the Encapsulation specification.
#[derive(Debug, PartialEq)]
pub enum Packet<P> {
    NullIdle { flow: u8 },
    NullAlign { flow: u8 },
    Normal(Normal<P>),
}

impl<P> Packet<P> {
    /// Retrieve the flow indicator of this packet
    pub fn flow(&self) -> u8 {
        match self {
            Self::NullIdle { flow } => *flow,
            Self::NullAlign { flow } => *flow,
            Self::Normal(p) => p.flow(),
        }
    }

    /// Check whether this packet is a null packet
    ///
    /// Returns [`true`] if the packet is a `null.idle` or a `null.align`
    /// packet.
    pub fn is_null(&self) -> bool {
        matches!(self, Self::NullIdle { .. } | Self::NullAlign { .. })
    }

    /// Transform into a [`Normal`] Encapsulation Structure
    ///
    /// Returns [`None`] if this packet is a null packet.
    pub fn into_normal(self) -> Option<Normal<P>> {
        match self {
            Self::Normal(n) => Some(n),
            _ => None,
        }
    }
}

impl<P> From<Normal<P>> for Packet<P> {
    fn from(normal: Normal<P>) -> Self {
        Self::Normal(normal)
    }
}

impl<'a, 'd, U> Decode<'a, 'd, U> for Packet<decoder::Scoped<'a, 'd, U>> {
    fn decode(decoder: &'a mut Decoder<'d, U>) -> Result<Self, Error> {
        if decoder.bytes_left() == 0 {
            // We need to make sure we don't decode a series of `null` packets
            // from nothing because of transparent decompression. Normal packets
            // are taken care of by `Decoder::split_data`.
            return Err(Error::InsufficientData(core::num::NonZeroUsize::MIN));
        }
        let length = decoder.read_bits(5)?;
        let flow = decoder.read_bits(2)?;
        let extend = decoder.read_bit()?;

        match core::num::NonZeroU8::new(length) {
            Some(length) => {
                let src_id = decoder.read_bits(decoder.hart_index_width())?;
                let timestamp = extend
                    .then(|| decoder.read_bits(8 * decoder.timestamp_width()))
                    .transpose()?;
                decoder::Scoped::new(decoder, length.get().into()).map(|payload| {
                    Normal {
                        flow,
                        src_id,
                        timestamp,
                        payload,
                    }
                    .into()
                })
            }
            _ if extend => Ok(Self::NullAlign { flow }),
            _ => Ok(Self::NullIdle { flow }),
        }
    }
}

/// Normal RISC-V Encapsulation [Packet]
///
/// This datatype represents a "Normal Encapsulation Structure" as describes in
/// Chapter 2.1 of the Encapsulation specification.
///
/// This type encapsulates a [`Decoder`], from which it will consume all
/// associated when [dropped][Drop::drop], leaving the decoder at the byte
/// boundary following the packet. Thus, the packet's data will be consumed
/// regardless of whether the payload was decoded or not and even if an error
/// occurred while decoding the payload.
#[derive(Debug, PartialEq)]
pub struct Normal<P> {
    flow: u8,
    src_id: u16,
    timestamp: Option<u64>,
    payload: P,
}

impl<P> Normal<P> {
    /// Retrieve the flow indicator of this packet
    pub fn flow(&self) -> u8 {
        self.flow
    }

    /// Retrieve the packet's source id
    ///
    /// Identifies the source (e.g. Trace encoder associated to a specific HART)
    /// of the packet.
    pub fn src_id(&self) -> u16 {
        self.src_id
    }

    /// Retrieve the packet's (outer) timestamp
    pub fn timestamp(&self) -> Option<u64> {
        self.timestamp
    }
}

impl<'a, 'd, U: unit::Unit> Normal<decoder::Scoped<'a, 'd, U>> {
    /// Decode the packet's E-Trace payload
    pub fn decode_payload(mut self) -> Result<payload::Payload<U::IOptions, U::DOptions>, Error> {
        let decoder = self.payload.decoder_mut();
        let width = decoder.trace_type_width();
        match decoder.read_bits::<u8>(width)? {
            0 => Decode::decode(decoder).map(payload::Payload::InstructionTrace),
            1 => Ok(payload::Payload::DataTrace),
            unknown => Err(Error::UnknownTraceType(unknown)),
        }
    }
}
