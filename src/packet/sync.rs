// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Synchronization payloads
//!
//! This module contains definitions of the various synchronization packets as
//! defined in section 7.1 Format 3 packets of the specification. This includes
//! the [`Synchronization`] type which may hold any of the subformats.

use crate::types::{trap, Privilege};

use super::unit::{self, Unit};
use super::{util, Decode, Decoder, Error};

/// Synchronization payload
///
/// Represents a format 3 packet.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Synchronization<I = unit::ReferenceIOptions, D = unit::ReferenceDOptions> {
    Start(Start),
    Trap(Trap),
    Context(Context),
    Support(Support<I, D>),
}

impl<I, D> Synchronization<I, D> {
    /// Check whether we got here without a branch being taken
    ///
    /// Returns [`false`] if the address was a branch target and [`true`] if the
    /// branch was not taken or the previous instruction was not a branch
    /// instruction. Returns [`None`] if the packet doesn't carry any address
    /// information.
    pub fn branch_not_taken(&self) -> Option<bool> {
        match self {
            Self::Start(start) => Some(start.branch),
            Self::Trap(trap) => Some(trap.branch),
            _ => None,
        }
    }

    /// Retrieve the [`Context`] from this payload
    ///
    /// Returns [`None`] if the payload does not contain a context. This is the
    /// case for [`Support`][Self::Support] payloads.
    pub fn as_context(&self) -> Option<&Context> {
        match self {
            Self::Start(start) => Some(&start.ctx),
            Self::Trap(trap) => Some(&trap.ctx),
            Self::Context(ctx) => Some(ctx),
            _ => None,
        }
    }
}

impl<I, D> From<Start> for Synchronization<I, D> {
    fn from(start: Start) -> Self {
        Self::Start(start)
    }
}

impl<I, D> From<Trap> for Synchronization<I, D> {
    fn from(trap: Trap) -> Self {
        Self::Trap(trap)
    }
}

impl<I, D> From<Context> for Synchronization<I, D> {
    fn from(ctx: Context) -> Self {
        Self::Context(ctx)
    }
}

impl<I, D> From<Support<I, D>> for Synchronization<I, D> {
    fn from(support: Support<I, D>) -> Self {
        Self::Support(support)
    }
}

impl<U: Unit> Decode<'_, '_, U> for Synchronization<U::IOptions, U::DOptions> {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        match decoder.read_bits::<u8>(2)? {
            0b00 => Start::decode(decoder).map(Into::into),
            0b01 => Trap::decode(decoder).map(Into::into),
            0b10 => Context::decode(decoder).map(Into::into),
            0b11 => Support::decode(decoder).map(Into::into),
            _ => unreachable!(),
        }
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

impl<U> Decode<'_, '_, U> for Start {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
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

impl<U> Decode<'_, '_, U> for Trap {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        let branch = decoder.read_bit()?;
        let ctx = Context::decode(decoder)?;
        let ecause = decoder.read_bits(decoder.widths().ecause.get())?;
        let interrupt = decoder.read_bit()?;
        let thaddr = decoder.read_bit()?;
        let address = util::read_address(decoder)?;
        let tval = if interrupt {
            None
        } else {
            Some(decoder.read_bits(decoder.widths().iaddress.get())?)
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
    pub time: Option<u64>,
    pub context: Option<u64>,
}

impl<U> Decode<'_, '_, U> for Context {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        let privilege = decoder
            .read_bits::<u8>(decoder.widths().privilege.get())?
            .try_into()
            .map_err(Error::UnknownPrivilege)?;
        let time = decoder
            .widths()
            .time
            .map(|w| decoder.read_bits(w.get()))
            .transpose()?;
        let context = decoder
            .widths()
            .context
            .map(|w| decoder.read_bits(w.get()))
            .transpose()?;
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
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct Support<I = unit::ReferenceIOptions, D = unit::ReferenceDOptions> {
    pub ienable: bool,
    pub encoder_mode: EncoderMode,
    pub qual_status: QualStatus,
    pub ioptions: I,
    pub denable: bool,
    pub dloss: bool,
    pub doptions: D,
}

impl<U: Unit> Decode<'_, '_, U> for Support<U::IOptions, U::DOptions> {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        let ienable = decoder.read_bit()?;
        let encoder_mode = decoder
            .read_bits::<u8>(decoder.unit().encoder_mode_width())?
            .try_into()
            .map_err(Error::UnknownEncoderMode)?;
        let qual_status = QualStatus::decode(decoder)?;
        let ioptions = U::decode_ioptions(decoder)?;
        let denable = decoder.read_bit()?;
        let dloss = decoder.read_bit()?;
        let doptions = U::decode_doptions(decoder)?;
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

impl Default for QualStatus {
    fn default() -> Self {
        Self::NoChange
    }
}

impl<U> Decode<'_, '_, U> for QualStatus {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
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

impl Default for EncoderMode {
    fn default() -> Self {
        Self::BranchTrace
    }
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
