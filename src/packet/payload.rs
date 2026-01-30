// Copyright (C) 2024, 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Definitions of various payloads

use core::fmt;

use crate::types::branch;

use super::decoder::{Decode, Decoder};
use super::encoder::{Encode, Encoder};
use super::{Error, ext, sync, unit, util};

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

impl<I: unit::IOptions, D> fmt::Display for Payload<I, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InstructionTrace(i) => fmt::Display::fmt(i, f),
            Self::DataTrace => write!(f, "DATA"),
        }
    }
}

/// An instruction trace payload
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum InstructionTrace<I = unit::ReferenceIOptions, D = unit::ReferenceDOptions> {
    Extension(ext::Extension),
    Branch(Branch),
    Address(AddressInfo),
    Synchronization(sync::Synchronization<I, D>),
}

impl<U: unit::Unit> Decode<'_, U> for InstructionTrace<U::IOptions, U::DOptions> {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        match decoder.read_bits::<u8>(2)? {
            0b00 => ext::Extension::decode(decoder).map(Into::into),
            0b01 => Branch::decode(decoder).map(Into::into),
            0b10 => AddressInfo::decode(decoder).map(Into::into),
            0b11 => sync::Synchronization::decode(decoder).map(Into::into),
            _ => unreachable!(),
        }
    }
}

impl<'d, U> Encode<'d, U> for InstructionTrace<U::IOptions, U::DOptions>
where
    U: unit::Unit,
    U::IOptions: Encode<'d, U>,
    U::DOptions: Encode<'d, U>,
{
    fn encode(&self, encoder: &mut Encoder<'d, U>) -> Result<(), Error> {
        match self {
            Self::Extension(ext) => {
                encoder.write_bits(0b00u8, 2)?;
                encoder.encode(ext)
            }
            Self::Branch(branch) => {
                encoder.write_bits(0b01u8, 2)?;
                encoder.encode(branch)
            }
            Self::Address(addr) => {
                encoder.write_bits(0b10u8, 2)?;
                encoder.encode(addr)
            }
            Self::Synchronization(sync) => {
                encoder.write_bits(0b11u8, 2)?;
                encoder.encode(sync)
            }
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
            Self::Extension(e) => e.get_address_info(),
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
            Self::Extension(e) => e.implicit_return_depth(),
            _ => None,
        }
    }
}

impl<I, D> From<ext::Extension> for InstructionTrace<I, D> {
    fn from(ex: ext::Extension) -> Self {
        Self::Extension(ex)
    }
}

impl<I, D> From<ext::BranchCount> for InstructionTrace<I, D> {
    fn from(count: ext::BranchCount) -> Self {
        Self::Extension(ext::Extension::BranchCount(count))
    }
}

impl<I, D> From<ext::JumpTargetIndex> for InstructionTrace<I, D> {
    fn from(idx: ext::JumpTargetIndex) -> Self {
        Self::Extension(ext::Extension::JumpTargetIndex(idx))
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

impl<I: unit::IOptions, D> fmt::Display for InstructionTrace<I, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Extension(e) => fmt::Display::fmt(e, f),
            Self::Branch(b) => write!(f, "BRANCH {b}"),
            Self::Address(a) => write!(f, "ADDR {a}"),
            Self::Synchronization(s) => fmt::Display::fmt(s, f),
        }
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

impl<U> Decode<'_, U> for Branch {
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

impl<U> Encode<'_, U> for Branch {
    fn encode(&self, encoder: &mut Encoder<U>) -> Result<(), Error> {
        if let Some(address) = self.address.as_ref() {
            let count = util::BranchCount(self.branch_map.count());
            encoder.encode(&count)?;
            encoder.write_bits(self.branch_map.raw_map(), count.field_length())?;
            encoder.encode(address)
        } else {
            encoder.encode(&util::BranchCount(0))?;
            encoder.write_bits(self.branch_map.raw_map(), 31)
        }
    }
}

impl fmt::Display for Branch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.branch_map, f)?;
        if let Some(address) = self.address {
            write!(f, ", {address}")?;
        }
        Ok(())
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

impl<U> Decode<'_, U> for AddressInfo {
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

impl<U> Encode<'_, U> for AddressInfo {
    fn encode(&self, encoder: &mut Encoder<U>) -> Result<(), Error> {
        util::write_address(encoder, self.address)?;
        encoder.write_differential_bit(self.notify)?;
        encoder.write_differential_bit(self.updiscon)?;
        util::write_implicit_return(encoder, self.irdepth)
    }
}

impl fmt::Display for AddressInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "address: {:0x}", self.address as u64)?;
        if self.address < 0 && let Some(addr) = self.address.checked_neg() {
            write!(f, " (-{addr:x})")?;
        }
        if self.notify {
            write!(f, ", notify")?;
        }
        if self.updiscon {
            write!(f, ", updiscon")?;
        }
        if let Some(irdepth) = self.irdepth {
            write!(f, ", irdepth: {irdepth}")?;
        }
        Ok(())
    }
}
