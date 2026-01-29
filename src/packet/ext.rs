// Copyright (C) 2026 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Extension payloads

use crate::types::branch;

use super::decoder::{Decode, Decoder};
use super::encoder::{Encode, Encoder};
use super::payload::AddressInfo;
use super::{Error, util};

/// Extension payload
///
/// Represents a format 0 packet.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Extension {
    BranchCount(BranchCount),
    JumpTargetIndex(JumpTargetIndex),
}

impl<U> Decode<'_, U> for Extension {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        match decoder.read_bits(decoder.widths().format0_subformat)? {
            0 => BranchCount::decode(decoder).map(Self::BranchCount),
            1 => JumpTargetIndex::decode(decoder).map(Self::JumpTargetIndex),
            s => Err(Error::UnknownFmt(0, Some(s))),
        }
    }
}

impl<U> Encode<'_, U> for Extension {
    fn encode(&self, encoder: &mut Encoder<U>) -> Result<(), Error> {
        match self {
            Self::BranchCount(branch) => encoder.encode(branch),
            Self::JumpTargetIndex(jti) => encoder.encode(jti),
        }
    }
}

/// Branch count payload
///
/// Represents a format 0, subformat 0 packet. It informs about the number of
/// correctly predicted branches.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BranchCount {
    /// Count of the number of correctly predicted branches, minus 31.
    pub branch_count: u32,
    pub branch_fmt: BranchFmt,
    pub address: Option<AddressInfo>,
}

impl<U> Decode<'_, U> for BranchCount {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        let branch_count = decoder.read_bits::<u32>(32)? - 31;
        let branch_fmt = BranchFmt::decode(decoder)?;
        let address = if branch_fmt == BranchFmt::NoAddr {
            None
        } else {
            Some(AddressInfo::decode(decoder)?)
        };
        Ok(BranchCount {
            branch_count,
            address,
            branch_fmt,
        })
    }
}

impl<U> Encode<'_, U> for BranchCount {
    fn encode(&self, encoder: &mut Encoder<U>) -> Result<(), Error> {
        encoder.write_bits(self.branch_count + 31, 32)?;
        encoder.encode(&self.branch_fmt)?;
        if let Some(address) = self.address.as_ref() {
            encoder.encode(address)?;
        }
        Ok(())
    }
}

/// Determines the layout of [`BranchCount`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BranchFmt {
    /// No address
    ///
    /// The packet does not contain an address, and the branch following the
    /// last correct prediction failed.
    NoAddr = 0,
    /// Address, success
    ///
    /// The packet contains an address. If this points to a branch instruction,
    /// then the branch was predicted correctly.
    Addr = 2,
    /// Address, failure
    ///
    /// The packet contains an address that points to a branch instruction. The
    /// prediction for that branch failed.
    AddrFail = 3,
}

impl<U> Decode<'_, U> for BranchFmt {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        match decoder.read_bits::<u8>(2)? {
            0b00 => Ok(BranchFmt::NoAddr),
            0b01 => Err(Error::BadBranchFmt),
            0b10 => Ok(BranchFmt::Addr),
            0b11 => Ok(BranchFmt::AddrFail),
            _ => unreachable!(),
        }
    }
}

impl<U> Encode<'_, U> for BranchFmt {
    fn encode(&self, encoder: &mut Encoder<U>) -> Result<(), Error> {
        let value: u8 = match self {
            Self::NoAddr => 0b00,
            Self::Addr => 0b10,
            Self::AddrFail => 0b11,
        };
        encoder.write_bits(value, 2)
    }
}

/// Jump target index payload
///
/// Represents a format 0, subformat 1 packet.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct JumpTargetIndex {
    /// Index of entry containing the jump's target address
    pub index: usize,
    pub branch_map: branch::Map,

    /// Implicit return depth
    pub irdepth: Option<usize>,
}

impl<U> Decode<'_, U> for JumpTargetIndex {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        let index = decoder.read_bits(decoder.widths().cache_index)?;
        let branch_map = util::BranchCount::decode(decoder)?.read_branch_map(decoder)?;
        let irdepth = util::read_implicit_return(decoder)?;
        Ok(JumpTargetIndex {
            index,
            branch_map,
            irdepth,
        })
    }
}

impl<U> Encode<'_, U> for JumpTargetIndex {
    fn encode(&self, encoder: &mut Encoder<U>) -> Result<(), Error> {
        encoder.write_bits(self.index, encoder.widths().cache_index)?;
        let count = util::BranchCount(self.branch_map.count());
        encoder.encode(&count)?;
        encoder.write_bits(self.branch_map.raw_map(), count.field_length())?;
        util::write_implicit_return(encoder, self.irdepth)
    }
}
