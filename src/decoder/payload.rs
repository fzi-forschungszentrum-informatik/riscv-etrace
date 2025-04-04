// Copyright (C) 2024 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

//! Implements all different payloads and their decoding.
use crate::types::{branch, trap, Privilege};

use super::{util, Decode, Decoder, Error};

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

impl Decode for BranchFmt {
    fn decode(decoder: &mut Decoder) -> Result<Self, Error> {
        match decoder.read_bits::<u8>(2)? {
            0b00 => Ok(BranchFmt::NoAddr),
            0b01 => Err(Error::BadBranchFmt),
            0b10 => Ok(BranchFmt::Addr),
            0b11 => Ok(BranchFmt::AddrFail),
            _ => unreachable!(),
        }
    }
}

/// Reports how or if the filter qualification changed.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum QualStatus {
    /// No change to filter qualification.
    NoChange,
    /// Qualification ended, preceding packet sent explicitly to indicate last qualification
    /// instruction.
    EndedRep,
    /// One or more instruction trace packets lost.
    TraceLost,
    /// Qualification ended, preceding packet    would have been sent anyway due to an updiscon,
    /// even if it wasn’t the last qualified instruction
    EndedNtr,
}

impl Decode for QualStatus {
    fn decode(decoder: &mut Decoder) -> Result<Self, Error> {
        Ok(match decoder.read_bits::<u8>(2)? {
            0b00 => QualStatus::NoChange,
            0b01 => QualStatus::EndedRep,
            0b10 => QualStatus::TraceLost,
            0b11 => QualStatus::EndedNtr,
            _ => unreachable!(),
        })
    }
}

/// Top level enum for all possible payload formats.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Payload {
    Extension(Extension),
    Branch(Branch),
    Address(AddressInfo),
    Synchronization(Synchronization),
}

impl Payload {
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

    pub fn get_address(&self) -> u64 {
        match self.get_address_info() {
            None => {
                if let Payload::Synchronization(Synchronization::Start(start)) = self {
                    start.address
                } else if let Payload::Synchronization(Synchronization::Trap(trap)) = self {
                    trap.address
                } else {
                    panic!("{:?} does not have an address", self)
                }
            }
            Some(addr_info) => addr_info.address,
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

impl From<Extension> for Payload {
    fn from(ex: Extension) -> Self {
        Self::Extension(ex)
    }
}

impl From<BranchCount> for Payload {
    fn from(count: BranchCount) -> Self {
        Self::Extension(Extension::BranchCount(count))
    }
}

impl From<JumpTargetIndex> for Payload {
    fn from(idx: JumpTargetIndex) -> Self {
        Self::Extension(Extension::JumpTargetIndex(idx))
    }
}

impl From<Branch> for Payload {
    fn from(branch: Branch) -> Self {
        Self::Branch(branch)
    }
}

impl From<AddressInfo> for Payload {
    fn from(addr: AddressInfo) -> Self {
        Self::Address(addr)
    }
}

impl From<Synchronization> for Payload {
    fn from(sync: Synchronization) -> Self {
        Self::Synchronization(sync)
    }
}

impl From<Start> for Payload {
    fn from(start: Start) -> Self {
        Self::Synchronization(start.into())
    }
}

impl From<Trap> for Payload {
    fn from(trap: Trap) -> Self {
        Self::Synchronization(trap.into())
    }
}

impl From<Context> for Payload {
    fn from(ctx: Context) -> Self {
        Self::Synchronization(ctx.into())
    }
}

impl From<Support> for Payload {
    fn from(support: Support) -> Self {
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

impl Decode for BranchCount {
    fn decode(decoder: &mut Decoder) -> Result<Self, Error> {
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

impl Decode for JumpTargetIndex {
    fn decode(decoder: &mut Decoder) -> Result<Self, Error> {
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

impl Decode for Branch {
    fn decode(decoder: &mut Decoder) -> Result<Self, Error> {
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

impl Decode for AddressInfo {
    fn decode(decoder: &mut Decoder) -> Result<Self, Error> {
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

/// #### Format 3
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Synchronization {
    Start(Start),
    Trap(Trap),
    Context(Context),
    Support(Support),
}

impl Synchronization {
    /// Check whether we got here without a branch being taken
    ///
    /// Returns `false` if the address was a branch target and `true` if the
    /// branch was not taken or the previous instruction was not a branch
    /// instruction. Returns `None` if the packet doesn't carry any address
    /// information.
    pub fn branch_not_taken(&self) -> Option<bool> {
        match self {
            Self::Start(start) => Some(start.branch),
            Self::Trap(trap) => Some(trap.branch),
            _ => None,
        }
    }

    pub fn get_privilege(&self) -> Option<Privilege> {
        match self {
            Self::Start(start) => Some(start.ctx.privilege),
            Self::Trap(trap) => Some(trap.ctx.privilege),
            Self::Context(ctx) => Some(ctx.privilege),
            _ => None,
        }
    }
}

impl From<Start> for Synchronization {
    fn from(start: Start) -> Self {
        Self::Start(start)
    }
}

impl From<Trap> for Synchronization {
    fn from(trap: Trap) -> Self {
        Self::Trap(trap)
    }
}

impl From<Context> for Synchronization {
    fn from(ctx: Context) -> Self {
        Self::Context(ctx)
    }
}

impl From<Support> for Synchronization {
    fn from(support: Support) -> Self {
        Self::Support(support)
    }
}

/// #### Format 3, sub format 0
/// Sent for the first traced instruction or when resynchronization is necessary.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Start {
    /// False, if the address is a taken branch instruction. True, if the branch was not taken
    /// or the instruction is not a branch.
    pub branch: bool,
    pub ctx: Context,
    /// Full address of the instruction.
    pub address: u64,
}

impl Decode for Start {
    fn decode(decoder: &mut Decoder) -> Result<Self, Error> {
        let branch = decoder.read_bit()?;
        let ctx = Context::decode(decoder)?;
        let address = util::read_address(decoder)?;
        Ok(Start {
            branch,
            ctx,
            address,
        })
    }
}

/// #### Format 3, sub format 1
/// Sent following an exception or interrupt.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Trap {
    /// False, if the address is a taken branch instruction. True, if the branch was not taken
    /// or the instruction is not a branch.
    pub branch: bool,
    pub ctx: Context,
    /// True, if the address points to the trap handler. False, if address points to the EPC for
    /// an exception at the target of an updiscon, and is undefined for other exceptions and interrupts.
    pub thaddr: bool,
    /// Full address of the instruction.
    pub address: u64,
    pub info: trap::Info,
}

impl Decode for Trap {
    fn decode(decoder: &mut Decoder) -> Result<Self, Error> {
        let branch = decoder.read_bit()?;
        let ctx = Context::decode(decoder)?;
        let ecause = decoder.read_bits(decoder.proto_conf.ecause_width_p)?;
        let kind = if decoder.read_bit()? {
            trap::Kind::Interrupt
        } else {
            trap::Kind::Exception
        };
        let thaddr = decoder.read_bit()?;
        let address = util::read_address(decoder)?;
        let tval = decoder.read_bits(decoder.proto_conf.iaddress_width_p)?;
        Ok(Trap {
            branch,
            ctx,
            thaddr,
            address,
            info: trap::Info { ecause, tval, kind },
        })
    }
}

/// #### Format 3, sub format 2
/// Informs that the context changed or used as part of other payloads.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Context {
    /// The privilege level of the reported instruction.
    pub privilege: Privilege,
    pub time: u64,
    pub context: u64,
}

impl Decode for Context {
    fn decode(decoder: &mut Decoder) -> Result<Self, Error> {
        let privilege = decoder
            .read_bits::<u8>(2)?
            .try_into()
            .map_err(Error::UnknownPrivilege)?;
        let time = decoder.read_bits(decoder.proto_conf.time_width_p)?;
        let context = decoder.read_bits(decoder.proto_conf.context_width_p)?;
        Ok(Context {
            privilege,
            time,
            context,
        })
    }
}

/// #### Format 3, sub format 3
/// Supporting information for the decoder.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Support {
    pub ienable: bool,
    pub encoder_mode: u64,
    pub qual_status: QualStatus,
    pub ioptions: u64,
    pub denable: bool,
    pub dloss: bool,
    pub doptions: u64,
}

impl Decode for Support {
    fn decode(decoder: &mut Decoder) -> Result<Self, Error> {
        let ienable = decoder.read_bit()?;
        let encoder_mode = decoder.read_bits(decoder.proto_conf.encoder_mode_n)?;
        let qual_status = QualStatus::decode(decoder)?;
        let ioptions = decoder.read_bits(decoder.proto_conf.ioptions_n)?;
        let denable = decoder.read_bit()?;
        let dloss = decoder.read_bit()?;
        let doptions = decoder.read_bits(4)?;
        Ok(Support {
            ienable,
            encoder_mode,
            qual_status,
            ioptions,
            denable,
            dloss,
            doptions,
        })
    }
}
