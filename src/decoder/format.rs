// Copyright (C) 2024 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

use super::payload::{self, Payload};
use super::{Decode, Decoder, Error};

#[derive(Debug, Eq, PartialEq)]
pub enum Format {
    Ext(Ext),
    Branch,
    Addr,
    Sync(Sync),
}

impl Format {
    pub fn decode_payload(&self, decoder: &mut Decoder) -> Result<Payload, Error> {
        match self {
            Self::Ext(Ext::BranchCount) => payload::BranchCount::decode(decoder).map(Into::into),
            Self::Ext(Ext::JumpTargetIndex) => {
                payload::JumpTargetIndex::decode(decoder).map(Into::into)
            }
            Self::Branch => payload::Branch::decode(decoder).map(Into::into),
            Self::Addr => payload::AddressInfo::decode(decoder).map(Into::into),
            Self::Sync(Sync::Start) => payload::Start::decode(decoder).map(Into::into),
            Self::Sync(Sync::Trap) => payload::Trap::decode(decoder).map(Into::into),
            Self::Sync(Sync::Context) => payload::Context::decode(decoder).map(Into::into),
            Self::Sync(Sync::Support) => payload::Support::decode(decoder).map(Into::into),
        }
    }
}

impl Decode for Format {
    fn decode(decoder: &mut Decoder) -> Result<Self, Error> {
        Ok(match decoder.read_bits::<u8>(2)? {
            0b00 => Self::Ext(Ext::decode(decoder)?),
            0b01 => Self::Branch,
            0b10 => Self::Addr,
            0b11 => Self::Sync(Sync::decode(decoder)?),
            _ => unreachable!(),
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Ext {
    BranchCount,
    JumpTargetIndex,
}

impl Decode for Ext {
    fn decode(decoder: &mut Decoder) -> Result<Self, Error> {
        Ok(if decoder.read_bit()? {
            Self::JumpTargetIndex
        } else {
            Self::BranchCount
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Sync {
    Start,
    Trap,
    Context,
    Support,
}

impl Decode for Sync {
    fn decode(decoder: &mut Decoder) -> Result<Self, Error> {
        Ok(match decoder.read_bits::<u8>(2)? {
            0b00 => Self::Start,
            0b01 => Self::Trap,
            0b10 => Self::Context,
            0b11 => Self::Support,
            _ => unreachable!(),
        })
    }
}
