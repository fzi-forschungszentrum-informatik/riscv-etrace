// Copyright (C) 2024 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

use super::payload::{self, Payload};
use super::{sync, Decode, Decoder, Error};

#[derive(Debug, Eq, PartialEq)]
pub enum Format {
    Ext(Ext),
    Branch,
    Addr,
    Sync(Sync),
}

impl Format {
    pub fn decode_payload<U>(&self, decoder: &mut Decoder<U>) -> Result<Payload, Error> {
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

impl<U> Decode<U> for Format {
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

#[derive(Debug, Eq, PartialEq)]
pub enum Ext {
    BranchCount,
    JumpTargetIndex,
}

impl<U> Decode<U> for Ext {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
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

impl<U> Decode<U> for Sync {
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
