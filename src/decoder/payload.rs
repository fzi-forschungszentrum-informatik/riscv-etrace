// Copyright (C) 2024, 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Definitions of various payloads

use crate::types::branch;

use super::{format, sync, unit, util, Decode, Decoder, Error};

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

impl<U> Decode<'_, '_, U> for BranchFmt {
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

/// An instruction trace payload
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Payload<I = unit::ReferenceIOptions, D = unit::ReferenceDOptions> {
    Extension(Extension),
    Branch(Branch),
    Address(AddressInfo),
    Synchronization(sync::Synchronization<I, D>),
}

impl<U: unit::Unit> Decode<'_, '_, U> for Payload<U::IOptions, U::DOptions> {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        format::Format::decode(decoder)?.decode_payload(decoder)
    }
}

impl<I, D> Payload<I, D> {
    /// Retrieve the [`AddressInfo`] in this payload
    ///
    /// Returns a reference to the [`AddressInfo`] contained in this payload or
    /// [`None`] if it does not contain one.
    pub fn get_address_info(&self) -> Option<&AddressInfo> {
        match self {
            Payload::Address(addr) => Some(addr),
            Payload::Branch(branch) => branch.address.as_ref(),
            Payload::Extension(Extension::BranchCount(branch_count)) => {
                branch_count.address.as_ref()
            }
            _ => None,
        }
    }

    /// Retrieve the implicit return depth
    ///
    /// Returns the number of entries on the return address stack (i.e. the
    /// entry number of the return that failed) or nested call count if the
    /// instruction reported by the packet is either:
    /// * following a return because its address differs from the predicted
    ///   return address at the top of the implicit_return return address stack,
    ///   or
    /// * the last retired before an exception, interrupt, privilege change or
    ///   resync because it is necessary to report the current address stack
    ///   depth or nested call count.
    ///
    /// Returns [`None`] otherwise.
    pub fn implicit_return_depth(&self) -> Option<usize> {
        match self {
            Payload::Address(a) => a.irdepth,
            Payload::Branch(b) => b.address.and_then(|a| a.irdepth),
            Payload::Extension(Extension::BranchCount(b)) => b.address.and_then(|a| a.irdepth),
            Payload::Extension(Extension::JumpTargetIndex(j)) => j.irdepth,
            _ => None,
        }
    }
}

impl<I, D> From<Extension> for Payload<I, D> {
    fn from(ex: Extension) -> Self {
        Self::Extension(ex)
    }
}

impl<I, D> From<BranchCount> for Payload<I, D> {
    fn from(count: BranchCount) -> Self {
        Self::Extension(Extension::BranchCount(count))
    }
}

impl<I, D> From<JumpTargetIndex> for Payload<I, D> {
    fn from(idx: JumpTargetIndex) -> Self {
        Self::Extension(Extension::JumpTargetIndex(idx))
    }
}

impl<I, D> From<Branch> for Payload<I, D> {
    fn from(branch: Branch) -> Self {
        Self::Branch(branch)
    }
}

impl<I, D> From<AddressInfo> for Payload<I, D> {
    fn from(addr: AddressInfo) -> Self {
        Self::Address(addr)
    }
}

impl<I, D> From<sync::Synchronization<I, D>> for Payload<I, D> {
    fn from(sync: sync::Synchronization<I, D>) -> Self {
        Self::Synchronization(sync)
    }
}

impl<I, D> From<sync::Start> for Payload<I, D> {
    fn from(start: sync::Start) -> Self {
        Self::Synchronization(start.into())
    }
}

impl<I, D> From<sync::Trap> for Payload<I, D> {
    fn from(trap: sync::Trap) -> Self {
        Self::Synchronization(trap.into())
    }
}

impl<I, D> From<sync::Context> for Payload<I, D> {
    fn from(ctx: sync::Context) -> Self {
        Self::Synchronization(ctx.into())
    }
}

impl<I, D> From<sync::Support<I, D>> for Payload<I, D> {
    fn from(support: sync::Support<I, D>) -> Self {
        Self::Synchronization(support.into())
    }
}

/// Extension payload
///
/// Represents a format 0 packet.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Extension {
    BranchCount(BranchCount),
    JumpTargetIndex(JumpTargetIndex),
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

impl<U> Decode<'_, '_, U> for BranchCount {
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

impl<U> Decode<'_, '_, U> for JumpTargetIndex {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        let index = decoder.read_bits(decoder.field_widths.cache_index)?;
        let branch_map = util::BranchCount::decode(decoder)?.read_branch_map(decoder)?;
        let irdepth = util::read_implicit_return(decoder)?;
        Ok(JumpTargetIndex {
            index,
            branch_map,
            irdepth,
        })
    }
}

/// Branch payload
///
/// Represents a format 1 packet. This packet includes branch information. It is
/// sent by the encoder when either the branch information must be reported (for
/// example because the branch map is full), or when the address of an
/// instruction must be reported, and there has been at least one branch since
/// the previous packet
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Branch {
    pub branch_map: branch::Map,
    pub address: Option<AddressInfo>,
}

impl<U> Decode<'_, '_, U> for Branch {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        use util::BranchCount;

        let count = BranchCount::decode(decoder)?;
        if count.is_zero() {
            let branch_map = BranchCount::FULL.read_branch_map(decoder)?;
            Ok(Branch {
                branch_map,
                address: None,
            })
        } else {
            let branch_map = count.read_branch_map(decoder)?;
            let address = AddressInfo::decode(decoder)?;
            Ok(Branch {
                branch_map,
                address: Some(address),
            })
        }
    }
}

/// Address info payload
///
/// Represents a format 2 packet. This payload contains only an instruction
/// address. It is sent by the encoder when the address of an instruction
/// must be reported, and there is no unreported branch information. The
/// address is differential (i.e. relative to the last reported address)
/// unless full address mode is enabled, but _not_ sign extended.
///
/// Inaddition to being a payload on its own, it also is used as part of other
/// payloads.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AddressInfo {
    /// Differential instruction address.
    pub address: u64,

    /// A notification was requested by a trigger
    ///
    /// If `true`, this packet is reporting an instruction that is not the
    /// target of an uninferable discontinuity because a notification was
    /// requested via a trigger.
    pub notify: bool,

    /// An uninferable discontinuity occured before a sync event
    ///
    /// If `true`, this packet is reporting the instruction following an
    /// uninferable discontinuity and is also the instruction before an
    /// exception, privilege change or resync (i.e. it will be followed
    /// immediately by a format 3 packet).
    pub updiscon: bool,

    /// Implicit return depth
    pub irdepth: Option<usize>,
}

impl<U> Decode<'_, '_, U> for AddressInfo {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        let address = util::read_address(decoder)?;
        let notify = decoder.read_differential_bit()?;
        let updiscon = decoder.read_differential_bit()?;
        let irdepth = util::read_implicit_return(decoder)?;
        Ok(AddressInfo {
            address,
            notify,
            updiscon,
            irdepth,
        })
    }
}
