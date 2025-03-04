// Copyright (C) 2024 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

use super::payload::{
    AddressInfo, Branch, Context, Extension, Payload, Start, Support, Synchronization, Trap,
};
use super::{Decode, Decoder, Error};

#[derive(Debug, Eq, PartialEq)]
pub enum Format {
    Ext(Ext),
    Branch,
    Addr,
    Sync(Sync),
}

impl Format {
    pub fn decode_payload(&self, decoder: &mut Decoder, slice: &[u8]) -> Result<Payload, Error> {
        Ok(match self {
            Format::Ext(Ext::BranchCount) => Payload::Extension(Extension::BranchCount(
                crate::decoder::payload::BranchCount::decode(decoder)?,
            )),
            Format::Ext(Ext::JumpTargetIndex) => Payload::Extension(Extension::JumpTargetIndex(
                crate::decoder::payload::JumpTargetIndex::decode(decoder)?,
            )),
            Format::Branch => Payload::Branch(Branch::decode(decoder)?),
            Format::Addr => Payload::Address(AddressInfo::decode(decoder)?),
            Format::Sync(Sync::Start) => {
                Payload::Synchronization(Synchronization::Start(Start::decode(decoder)?))
            }
            Format::Sync(Sync::Trap) => {
                Payload::Synchronization(Synchronization::Trap(Trap::decode(decoder)?))
            }
            Format::Sync(Sync::Context) => {
                Payload::Synchronization(Synchronization::Context(Context::decode(decoder)?))
            }
            Format::Sync(Sync::Support) => {
                Payload::Synchronization(Synchronization::Support(Support::decode(decoder)?))
            }
        })
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
            Ext::JumpTargetIndex
        } else {
            Ext::BranchCount
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
            0b00 => Sync::Start,
            0b01 => Sync::Trap,
            0b10 => Sync::Context,
            0b11 => Sync::Support,
            _ => unreachable!(),
        })
    }
}
