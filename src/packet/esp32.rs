// Copyright (C) 2024 - 2026 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Types and utilities for the RISC-V Encapsulation specification
//!
//! This module provides types and utilities for processing packets following
//! the [Unformatted Trace & Diagnostic Data Packet Encapsulation for
//! RISC-V][encap] specification.
//!
//! [encap]: <https://github.com/riscv-non-isa/e-trace-encap/>

use super::decoder::{Decode, Decoder};
//use super::encoder::{Encode, Encoder};
use super::{Error, payload, unit};

/// RISC-V ESP32 Format
///
/// This datatype represents the instruction trace packet described in Chapter 2 of the ESP32C6 Reference Manual
/// of the Encapsulation specification.
#[derive(Clone, Debug, PartialEq)]
pub enum Packet<P = payload::Payload> {
    Null,
    Normal(Normal<P>),
}

impl<P> Packet<P> {
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
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

impl<'d, U> TryFrom<Packet<Decoder<'d, U>>> for Packet<payload::Payload<U::IOptions, U::DOptions>>
where
    U: unit::Unit,
{
    type Error = Error;

    fn try_from(packet: Packet<Decoder<'d, U>>) -> Result<Self, Self::Error> {
        match packet {
            Packet::Null => Ok(Self::Null),
            Packet::Normal(p) => p.try_into().map(Self::Normal),
        }
    }
}

impl<'d, U> Decode<'d, U> for Packet<payload::Payload<U::IOptions, U::DOptions>>
where
    U: unit::Unit + Clone,
{
    fn decode(decoder: &mut Decoder<'d, U>) -> Result<Self, Error> {
        Packet::<Decoder<_>>::decode(decoder).and_then(TryFrom::try_from)
    }
}

impl<'d, U: Clone> Decode<'d, U> for Packet<Decoder<'d, U>> {
    fn decode(decoder: &mut Decoder<'d, U>) -> Result<Self, Error> {
        if decoder.bytes_left() == 0 {
            // We need to make sure we don't decode a series of `null` packets
            // from nothing because of transparent decompression. Normal packets
            // are taken care of by `Decoder::split_data`.
            return Err(Error::InsufficientData(core::num::NonZeroUsize::MIN));
        }
        let length = decoder.read_bits(5)?;
        let placeholder: u8 = decoder.read_bits(3)?; // placeholder 
        let index = decoder.read_bits(16)?;

        if placeholder != 0 {
            return Err(Error::PlaceholderNonZero(placeholder));
        }
        if length == 0 {
            return Ok(Self::Null);
        }

        if length < 4 {
            return Err(Error::InvalidDataLength(length));
        }

        let payload_length = usize::from(length) - 3; // payload length = length - header length
        let payload = decoder.split_off_to(payload_length)?;

        Ok(Normal { index, payload }.into())
    }
}

/// Normal RISC-V ESP32 [Packet]
#[derive(Clone, Debug, PartialEq)]
pub struct Normal<P> {
    index: u16,
    payload: P,
}

impl<P> Normal<P> {
    /// Create a new "Normal ESP32 Structure"
    pub fn new(index: u16, payload: P) -> Self {
        Self { index, payload }
    }

    pub fn index(&self) -> u16 {
        self.index
    }

    /// Retrieve the packet's payload
    pub fn payload(&self) -> &P {
        &self.payload
    }

    /// Get a mutable reference to the packet's payload
    pub fn payload_mut(&mut self) -> &mut P {
        &mut self.payload
    }
}

impl<'d, U: unit::Unit> Normal<Decoder<'d, U>> {
    /// Decode the packet's E-Trace payload
    pub fn decode_payload(mut self) -> Result<payload::Payload<U::IOptions, U::DOptions>, Error> {
        // ESP32 only supports Instruction Traces
        Decode::decode(&mut self.payload).map(payload::Payload::InstructionTrace)
    }
}

impl<'d, U> TryFrom<Normal<Decoder<'d, U>>> for Normal<payload::Payload<U::IOptions, U::DOptions>>
where
    U: unit::Unit,
{
    type Error = Error;

    fn try_from(normal: Normal<Decoder<'d, U>>) -> Result<Self, Self::Error> {
        let index = normal.index();
        let decoded_payload = normal.decode_payload()?;
        Ok(Self::new(index, decoded_payload))
    }
}

impl<U: unit::Unit> TryFrom<Normal<Decoder<'_, U>>> for payload::Payload<U::IOptions, U::DOptions> {
    type Error = Error;

    fn try_from(normal: Normal<Decoder<'_, U>>) -> Result<Self, Self::Error> {
        normal.decode_payload()
    }
}
