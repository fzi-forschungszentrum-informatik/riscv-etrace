// Copyright (C) 2024 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Definitions of various payloads

use crate::types::{branch, Privilege};

use super::{sync, unit, util, Decode, Decoder, Error};

/// Determines the layout of [BranchCount].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BranchFmt {
    /// Packet does not contain an address, and the branch following the last correct prediction
    /// failed.
    NoAddr = 0,
    /// Packet contains an address. If this points to a branch instruction, then the
    /// branch was predicted correctly
    Addr = 2,
    /// Packet contains an address that points to a branch which failed the prediction.
    AddrFail = 3,
}

impl<U> Decode<U> for BranchFmt {
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

/// Top level enum for all possible payload formats.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Payload<I = unit::ReferenceIOptions> {
    Extension(Extension),
    Branch(Branch),
    Address(AddressInfo),
    Synchronization(sync::Synchronization<I>),
}

impl<I> Payload<I> {
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
    /// Returns `None` otherwise.
    pub fn implicit_return_depth(&self) -> Option<usize> {
        match self {
            Payload::Address(a) => a.irdepth,
            Payload::Branch(b) => b.address.and_then(|a| a.irdepth),
            Payload::Extension(Extension::BranchCount(b)) => b.address.and_then(|a| a.irdepth),
            Payload::Extension(Extension::JumpTargetIndex(j)) => j.irdepth,
            _ => None,
        }
    }

    pub fn get_branches(&self) -> Option<u8> {
        match self {
            Payload::Branch(branch) => Some(branch.branch_map.count()),
            _ => None,
        }
    }

    pub fn get_privilege(&self) -> Option<Privilege> {
        if let Self::Synchronization(sync) = self {
            sync.get_privilege()
        } else {
            None
        }
    }
}

impl<I> From<Extension> for Payload<I> {
    fn from(ex: Extension) -> Self {
        Self::Extension(ex)
    }
}

impl<I> From<BranchCount> for Payload<I> {
    fn from(count: BranchCount) -> Self {
        Self::Extension(Extension::BranchCount(count))
    }
}

impl<I> From<JumpTargetIndex> for Payload<I> {
    fn from(idx: JumpTargetIndex) -> Self {
        Self::Extension(Extension::JumpTargetIndex(idx))
    }
}

impl<I> From<Branch> for Payload<I> {
    fn from(branch: Branch) -> Self {
        Self::Branch(branch)
    }
}

impl<I> From<AddressInfo> for Payload<I> {
    fn from(addr: AddressInfo) -> Self {
        Self::Address(addr)
    }
}

impl<I> From<sync::Synchronization<I>> for Payload<I> {
    fn from(sync: sync::Synchronization<I>) -> Self {
        Self::Synchronization(sync)
    }
}

impl<I> From<sync::Start> for Payload<I> {
    fn from(start: sync::Start) -> Self {
        Self::Synchronization(start.into())
    }
}

impl<I> From<sync::Trap> for Payload<I> {
    fn from(trap: sync::Trap) -> Self {
        Self::Synchronization(trap.into())
    }
}

impl<I> From<sync::Context> for Payload<I> {
    fn from(ctx: sync::Context) -> Self {
        Self::Synchronization(ctx.into())
    }
}

impl<I> From<sync::Support<I>> for Payload<I> {
    fn from(support: sync::Support<I>) -> Self {
        Self::Synchronization(support.into())
    }
}

/// #### Format 0
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Extension {
    BranchCount(BranchCount),
    JumpTargetIndex(JumpTargetIndex),
}

/// #### Format 0, sub format 0
/// Extension to report the number of correctly predicted branches.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BranchCount {
    /// Count of the number of correctly predicted branches, minus 31.
    pub branch_count: u32,
    pub branch_fmt: BranchFmt,
    pub address: Option<AddressInfo>,
}

impl<U> Decode<U> for BranchCount {
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

/// #### Format 0, sub format 1
/// Extension to report the jump target index.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct JumpTargetIndex {
    /// Jump target cache index of entry containing target address.
    pub index: usize,
    pub branch_map: branch::Map,

    /// Implicit return depth
    pub irdepth: Option<usize>,
}

impl<U> Decode<U> for JumpTargetIndex {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        let index = decoder.read_bits(decoder.proto_conf.cache_size_p)?;
        let branch_map = util::BranchCount::decode(decoder)?.read_branch_map(decoder)?;
        let irdepth = util::read_implicit_return(decoder)?;
        Ok(JumpTargetIndex {
            index,
            branch_map,
            irdepth,
        })
    }
}

/// #### Format 1
/// This packet includes branch information, and is used when either the branch information must be
/// reported (for example because the branch map is full), or when the address of an instruction must
/// be reported, and there has been at least one branch since the previous packet
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Branch {
    pub branch_map: branch::Map,
    pub address: Option<AddressInfo>,
}

impl<U> Decode<U> for Branch {
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

/// #### Format 2
/// This packet contains only an instruction address, and is used when the address of an instruction
/// must be reported, and there is no unreported branch information. The address is in differential
/// format unless full address mode is enabled.
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

impl<U> Decode<U> for AddressInfo {
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
