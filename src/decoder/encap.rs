// Copyright (C) 2024, 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Types and utilities for the RISC-V Encapsulation specification
//!
//! This module provides types and utilities for processing packets following
//! the [Unformatted Trace & Diagnostic Data Packet Encapsulation for
//! RISC-V][encap] specification.
//!
//! [encap]: <https://github.com/riscv-non-isa/e-trace-encap/>

use super::{payload, unit, Decode, Decoder, Error};

/// ETrace payload of an Encapsulation packet
///
/// This datatype represents a payload as describes in Chapter 2.1.4 and Chapter
/// 3.3 of the Encapsulation specification.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Payload<I, D> {
    InstructionTrace(payload::Payload<I, D>),
    DataTrace,
}

impl<I, D> Payload<I, D> {
    /// Retrieve the encapsulated instruction trace payload
    ///
    /// Returns [None] if this payload is not an instruction trace payload.
    pub fn as_instruction_trace(&self) -> Option<&payload::Payload<I, D>> {
        match self {
            Payload::InstructionTrace(p) => Some(p),
            _ => None,
        }
    }
}

impl<I, D> From<payload::Payload<I, D>> for Payload<I, D> {
    fn from(p: payload::Payload<I, D>) -> Self {
        Self::InstructionTrace(p)
    }
}

impl<I, D> TryFrom<Payload<I, D>> for payload::Payload<I, D> {
    type Error = Payload<I, D>;

    fn try_from(payload: Payload<I, D>) -> Result<Self, Self::Error> {
        match payload {
            Payload::InstructionTrace(p) => Ok(p),
            p => Err(p),
        }
    }
}

impl<U: unit::Unit> Decode<'_, '_, U> for Payload<U::IOptions, U::DOptions> {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        match decoder.read_bits::<u8>(decoder.trace_type_width)? {
            0 => Decode::decode(decoder).map(Self::InstructionTrace),
            unknown => Err(Error::UnknownTraceType(unknown)),
        }
    }
}
