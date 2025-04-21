// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Synchronization payloads
//!
//! This module contains definitions of the various synchronization packets as
//! defined in section 7.1 Format 3 packets of the specification. This includes
//! the [Synchronization] type which may hold any of the subformats.

use crate::types::{trap, Privilege};

use super::{util, Decode, Decoder, Error};

/// Synchronization payload
///
/// Represents a format 3 packet.
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

    /// Retrieve the [Context::privilege] from this payload
    ///
    /// Returns [None] if the payload does not contain a context. This is the
    /// case for [Support][Self::Support] packets.
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

/// Start of trace
///
/// Represents a format 3, subformat 0 packet. It is sent by the encoder for the
/// first traced instruction or when resynchronization is necessary.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Start {
    /// False, if the address is a taken branch instruction. True, if the branch
    /// was not taken or the instruction is not a branch.
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

/// Trap packet
///
/// Represents a format 3, subformat 1 packet. It is sent by the encoder
/// following an exception or interrupt.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Trap {
    /// `false`, if the address is a taken branch instruction. `true`, if the
    /// branch was not taken or the instruction is not a branch.
    pub branch: bool,
    pub ctx: Context,
    /// `true`, if the address points to the trap handler. `false`, if address
    /// points to the EPC for an exception at the target of an updiscon, and is
    /// undefined for other exceptions and interrupts.
    pub thaddr: bool,
    /// Full address of the instruction
    pub address: u64,
    pub info: trap::Info,
}

impl Decode for Trap {
    fn decode(decoder: &mut Decoder) -> Result<Self, Error> {
        let branch = decoder.read_bit()?;
        let ctx = Context::decode(decoder)?;
        let ecause = decoder.read_bits(decoder.proto_conf.ecause_width_p)?;
        let interrupt = decoder.read_bit()?;
        let thaddr = decoder.read_bit()?;
        let address = util::read_address(decoder)?;
        let tval = if interrupt {
            None
        } else {
            Some(decoder.read_bits(decoder.proto_conf.iaddress_width_p)?)
        };
        Ok(Trap {
            branch,
            ctx,
            thaddr,
            address,
            info: trap::Info { ecause, tval },
        })
    }
}

/// Context packet
///
/// Represents a format 3, subformat 2 packet. It informs about a changed
/// context. It is also used as part of other payloads.
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

/// Supporting information for the decoder.
///
/// Represents a format 3, subformat 3 packet.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Support {
    pub ienable: bool,
    pub encoder_mode: EncoderMode,
    pub qual_status: QualStatus,
    pub ioptions: u64,
    pub denable: bool,
    pub dloss: bool,
    pub doptions: u64,
}

impl Decode for Support {
    fn decode(decoder: &mut Decoder) -> Result<Self, Error> {
        let ienable = decoder.read_bit()?;
        let encoder_mode = decoder
            .read_bits::<u8>(decoder.proto_conf.encoder_mode_n)?
            .try_into()
            .map_err(Error::UnknownEncoderMode)?;
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

/// Representation of a change to the filter qualification
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum QualStatus {
    /// No change to filter qualification.
    NoChange,
    /// Qualification ended, preceding packet sent explicitly to indicate last
    /// qualification instruction.
    EndedRep,
    /// One or more instruction trace packets lost.
    TraceLost,
    /// Qualification ended, preceding packet would have been sent anyway due to
    /// an updiscon, even if it wasn’t the last qualified instruction
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

/// Mode the encoder is operating in
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EncoderMode {
    BranchTrace,
}

impl TryFrom<u8> for EncoderMode {
    type Error = u8;

    fn try_from(num: u8) -> Result<Self, Self::Error> {
        match num {
            0 => Ok(Self::BranchTrace),
            e => Err(e),
        }
    }
}
