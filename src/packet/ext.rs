// Copyright (C) 2026 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Extension payloads

use core::fmt;

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

impl Extension {
    /// Retrieve the [`AddressInfo`] in this payload
    ///
    /// Returns a reference to the [`AddressInfo`] contained in this payload or
    /// [`None`] if it does not contain one.
    pub fn get_address_info(&self) -> Option<&AddressInfo> {
        match self {
            Self::BranchCount(b) => b.kind.address_info(),
            _ => None,
        }
    }

    /// Retrieve the implicit return depth
    pub fn implicit_return_depth(&self) -> Option<usize> {
        match self {
            Self::BranchCount(b) => b.kind.address_info().and_then(|a| a.irdepth),
            Self::JumpTargetIndex(j) => j.irdepth,
        }
    }
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
    pub kind: BranchKind,
}

impl<U> Decode<'_, U> for BranchCount {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        let branch_count = decoder.read_bits::<u32>(32)? - 31;
        let kind = BranchKind::decode(decoder)?;
        Ok(BranchCount { branch_count, kind })
    }
}

impl<U> Encode<'_, U> for BranchCount {
    fn encode(&self, encoder: &mut Encoder<U>) -> Result<(), Error> {
        encoder.write_bits(self.branch_count + 31, 32)?;
        encoder.encode(&self.kind)
    }
}

/// Determines the layout of [`BranchCount`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BranchKind {
    /// No address
    ///
    /// The packet does not contain an address, and the branch following the
    /// last correct prediction failed.
    NoAddr,
    /// Address, success
    ///
    /// The packet contains an address. If this points to a branch instruction,
    /// then the branch was predicted correctly.
    Addr(AddressInfo),
    /// Address, failure
    ///
    /// The packet contains an address that points to a branch instruction. The
    /// prediction for that branch failed.
    AddrFail(AddressInfo),
}

impl BranchKind {
    /// Retrieve the [`AddressInfo`] in this branch kind
    pub fn address_info(&self) -> Option<&AddressInfo> {
        match self {
            Self::Addr(a) => Some(a),
            Self::AddrFail(a) => Some(a),
            _ => None,
        }
    }
}

impl<U> Decode<'_, U> for BranchKind {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        match decoder.read_bits::<u8>(2)? {
            0b00 => Ok(Self::NoAddr),
            0b01 => Err(Error::BadBranchFmt),
            0b10 => decoder.decode().map(Self::Addr),
            0b11 => decoder.decode().map(Self::AddrFail),
            _ => unreachable!(),
        }
    }
}

impl<U> Encode<'_, U> for BranchKind {
    fn encode(&self, encoder: &mut Encoder<U>) -> Result<(), Error> {
        match self {
            Self::NoAddr => encoder.write_bits(0b00u8, 2),
            Self::Addr(info) => {
                encoder.write_bits(0b10u8, 2)?;
                encoder.encode(info)
            }
            Self::AddrFail(info) => {
                encoder.write_bits(0b11u8, 2)?;
                encoder.encode(info)
            }
        }
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

impl fmt::Display for JumpTargetIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "index: {}, {}", self.index, self.branch_map)?;
        if let Some(irdepth) = self.irdepth {
            write!(f, ", irdepth: {irdepth}")?;
        }
        Ok(())
    }
}
