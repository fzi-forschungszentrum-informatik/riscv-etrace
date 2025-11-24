// Copyright (C) 2024, 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Definitions of various payloads

use crate::types::branch;

use super::decoder::{Decode, Decoder};
use super::encoder::{Encode, Encoder};
use super::{sync, unit, util, Error};

/// An E-Trace payload
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Payload<I = unit::ReferenceIOptions, D = unit::ReferenceDOptions> {
    /// An instruction trace payload
    InstructionTrace(InstructionTrace<I, D>),
    /// A data trace payload
    DataTrace,
}

impl<I, D> Payload<I, D> {
    /// Retrieve the encapsulated instruction trace payload
    ///
    /// Returns [None] if this payload is not an instruction trace payload.
    pub fn as_instruction_trace(&self) -> Option<&InstructionTrace<I, D>> {
        match self {
            Payload::InstructionTrace(p) => Some(p),
            _ => None,
        }
    }
}

impl<I, D> From<InstructionTrace<I, D>> for Payload<I, D> {
    fn from(p: InstructionTrace<I, D>) -> Self {
        Self::InstructionTrace(p)
    }
}

impl<I, D> TryFrom<Payload<I, D>> for InstructionTrace<I, D> {
    type Error = Payload<I, D>;

    fn try_from(payload: Payload<I, D>) -> Result<Self, Self::Error> {
        match payload {
            Payload::InstructionTrace(p) => Ok(p),
            p => Err(p),
        }
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

/// An instruction trace payload
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum InstructionTrace<I = unit::ReferenceIOptions, D = unit::ReferenceDOptions> {
    Extension(Extension),
    Branch(Branch),
    Address(AddressInfo),
    Synchronization(sync::Synchronization<I, D>),
}

impl<U: unit::Unit> Decode<'_, '_, U> for InstructionTrace<U::IOptions, U::DOptions> {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        match decoder.read_bits::<u8>(2)? {
            0b00 => Extension::decode(decoder).map(Into::into),
            0b01 => Branch::decode(decoder).map(Into::into),
            0b10 => AddressInfo::decode(decoder).map(Into::into),
            0b11 => sync::Synchronization::decode(decoder).map(Into::into),
            _ => unreachable!(),
        }
    }
}

impl<I, D> InstructionTrace<I, D> {
    /// Retrieve the [`AddressInfo`] in this payload
    ///
    /// Returns a reference to the [`AddressInfo`] contained in this payload or
    /// [`None`] if it does not contain one.
    pub fn get_address_info(&self) -> Option<&AddressInfo> {
        match self {
            Self::Address(addr) => Some(addr),
            Self::Branch(branch) => branch.address.as_ref(),
            Self::Extension(Extension::BranchCount(branch_count)) => branch_count.address.as_ref(),
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
            Self::Address(a) => a.irdepth,
            Self::Branch(b) => b.address.and_then(|a| a.irdepth),
            Self::Extension(Extension::BranchCount(b)) => b.address.and_then(|a| a.irdepth),
            Self::Extension(Extension::JumpTargetIndex(j)) => j.irdepth,
            _ => None,
        }
    }
}

impl<I, D> From<Extension> for InstructionTrace<I, D> {
    fn from(ex: Extension) -> Self {
        Self::Extension(ex)
    }
}

impl<I, D> From<BranchCount> for InstructionTrace<I, D> {
    fn from(count: BranchCount) -> Self {
        Self::Extension(Extension::BranchCount(count))
    }
}

impl<I, D> From<JumpTargetIndex> for InstructionTrace<I, D> {
    fn from(idx: JumpTargetIndex) -> Self {
        Self::Extension(Extension::JumpTargetIndex(idx))
    }
}

impl<I, D> From<Branch> for InstructionTrace<I, D> {
    fn from(branch: Branch) -> Self {
        Self::Branch(branch)
    }
}

impl<I, D> From<AddressInfo> for InstructionTrace<I, D> {
    fn from(addr: AddressInfo) -> Self {
        Self::Address(addr)
    }
}

impl<I, D> From<sync::Synchronization<I, D>> for InstructionTrace<I, D> {
    fn from(sync: sync::Synchronization<I, D>) -> Self {
        Self::Synchronization(sync)
    }
}

impl<I, D> From<sync::Start> for InstructionTrace<I, D> {
    fn from(start: sync::Start) -> Self {
        Self::Synchronization(start.into())
    }
}

impl<I, D> From<sync::Trap> for InstructionTrace<I, D> {
    fn from(trap: sync::Trap) -> Self {
        Self::Synchronization(trap.into())
    }
}

impl<I, D> From<sync::Context> for InstructionTrace<I, D> {
    fn from(ctx: sync::Context) -> Self {
        Self::Synchronization(ctx.into())
    }
}

impl<I, D> From<sync::Support<I, D>> for InstructionTrace<I, D> {
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

impl<U> Decode<'_, '_, U> for Extension {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        match decoder.read_bits(decoder.widths().format0_subformat)? {
            0 => BranchCount::decode(decoder).map(Self::BranchCount),
            1 => JumpTargetIndex::decode(decoder).map(Self::JumpTargetIndex),
            s => Err(Error::UnknownFmt(0, Some(s))),
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
/// unless full address mode is enabled. The address is always sign extended.
///
/// Inaddition to being a payload on its own, it also is used as part of other
/// payloads.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AddressInfo {
    /// Differential instruction address.
    pub address: i64,

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
