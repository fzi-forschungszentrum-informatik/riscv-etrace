// Copyright (C) 2024, 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Utilties for decoding a payload's format and subformat

use super::payload::{self, InstructionTrace};
use super::{sync, unit, Decode, Decoder, Error};

/// [`Payload`] format and subformat
#[derive(Debug, Eq, PartialEq)]
pub enum Format {
    Ext(Ext),
    Branch,
    Addr,
    Sync(Sync),
}

impl Format {
    /// Decode a [`Payload`] appropriate for this format
    pub fn decode_payload<U: unit::Unit>(
        &self,
        decoder: &mut Decoder<U>,
    ) -> Result<InstructionTrace<U::IOptions, U::DOptions>, Error> {
        match self {
            Self::Ext(Ext::BranchCount) => payload::BranchCount::decode(decoder).map(Into::into),
            Self::Ext(Ext::JumpTargetIndex) => {
                payload::JumpTargetIndex::decode(decoder).map(Into::into)
            }
            Self::Branch => payload::Branch::decode(decoder).map(Into::into),
            Self::Addr => payload::AddressInfo::decode(decoder).map(Into::into),
            Self::Sync(Sync::Start) => sync::Start::decode(decoder).map(Into::into),
            Self::Sync(Sync::Trap) => sync::Trap::decode(decoder).map(Into::into),
            Self::Sync(Sync::Context) => sync::Context::decode(decoder).map(Into::into),
            Self::Sync(Sync::Support) => sync::Support::decode(decoder).map(Into::into),
        }
    }
}

impl<U> Decode<'_, '_, U> for Format {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        Ok(match decoder.read_bits::<u8>(2)? {
            0b00 => Self::Ext(Ext::decode(decoder)?),
            0b01 => Self::Branch,
            0b10 => Self::Addr,
            0b11 => Self::Sync(Sync::decode(decoder)?),
            _ => unreachable!(),
        })
    }
}

/// Extension subformats
#[derive(Debug, Eq, PartialEq)]
pub enum Ext {
    BranchCount,
    JumpTargetIndex,
}

impl<U> Decode<'_, '_, U> for Ext {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        match decoder.read_bits(decoder.field_widths.format0_subformat)? {
            0 => Ok(Self::BranchCount),
            1 => Ok(Self::JumpTargetIndex),
            s => Err(Error::UnknownFmt(0, Some(s))),
        }
    }
}

/// Synchronization subformats
#[derive(Debug, Eq, PartialEq)]
pub enum Sync {
    Start,
    Trap,
    Context,
    Support,
}

impl<U> Decode<'_, '_, U> for Sync {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        Ok(match decoder.read_bits::<u8>(2)? {
            0b00 => Self::Start,
            0b01 => Self::Trap,
            0b10 => Self::Context,
            0b11 => Self::Support,
            _ => unreachable!(),
        })
    }
}
