// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Synchronization payloads
//!
//! This module contains definitions of the various synchronization packets as
//! defined in section 7.1 Format 3 packets of the specification. This includes
//! the [`Synchronization`] type which may hold any of the subformats.

use crate::types::{self, Privilege, trap};

use super::decoder::{Decode, Decoder};
use super::encoder::{Encode, Encoder};
use super::unit::{self, Unit};
use super::{Error, util};

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

impl<'d, U> Encode<'d, U> for Synchronization<U::IOptions, U::DOptions>
where
    U: Unit,
    U::IOptions: Encode<'d, U>,
    U::DOptions: Encode<'d, U>,
{
    fn encode(&self, encoder: &mut Encoder<'d, U>) -> Result<(), Error> {
        match self {
            Self::Start(start) => {
                encoder.write_bits(0b00u8, 2)?;
                encoder.encode(start)
            }
            Self::Trap(trap) => {
                encoder.write_bits(0b01u8, 2)?;
                encoder.encode(trap)
            }
            Self::Context(ctx) => {
                encoder.write_bits(0b10u8, 2)?;
                encoder.encode(ctx)
            }
            Self::Support(support) => {
                encoder.write_bits(0b11u8, 2)?;
                encoder.encode(support)
            }
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

impl<U> Encode<'_, U> for Start {
    fn encode(&self, encoder: &mut Encoder<U>) -> Result<(), Error> {
        encoder.write_bit(self.branch)?;
        encoder.encode(&self.ctx)?;
        util::write_address(encoder, self.address)
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

impl<U> Encode<'_, U> for Trap {
    fn encode(&self, encoder: &mut Encoder<U>) -> Result<(), Error> {
        encoder.write_bit(self.branch)?;
        encoder.encode(&self.ctx)?;
        encoder.write_bits(self.info.ecause, encoder.widths().ecause.get())?;
        encoder.write_bit(self.info.tval.is_none())?;
        encoder.write_bit(self.thaddr)?;
        util::write_address(encoder, self.address)?;
        if let Some(tval) = self.info.tval {
            encoder.write_bits(tval, encoder.widths().iaddress.get())?;
        }
        Ok(())
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
    pub context: u64,
}

impl From<&Context> for types::Context {
    fn from(ctx: &Context) -> Self {
        Self {
            privilege: ctx.privilege,
            context: ctx.context,
        }
    }
}

impl From<Context> for types::Context {
    fn from(ctx: Context) -> Self {
        (&ctx).into()
    }
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
        let context_width = decoder.widths().context.map(Into::into).unwrap_or_default();
        let context = decoder.read_bits(context_width)?;
        Ok(Context {
            privilege,
            time,
            context,
        })
    }
}

impl<U> Encode<'_, U> for Context {
    fn encode(&self, encoder: &mut Encoder<U>) -> Result<(), Error> {
        encoder.write_bits(u8::from(self.privilege), encoder.widths().privilege.get())?;
        if let Some(width) = encoder.widths().time {
            encoder.write_bits(self.time.unwrap_or_default(), width.get())?;
        }
        if let Some(width) = encoder.widths().context {
            encoder.write_bits(self.context, width.get())?;
        }
        Ok(())
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

impl<'d, U> Encode<'d, U> for Support<U::IOptions, U::DOptions>
where
    U: Unit,
    U::IOptions: Encode<'d, U>,
    U::DOptions: Encode<'d, U>,
{
    fn encode(&self, encoder: &mut Encoder<'d, U>) -> Result<(), Error> {
        encoder.write_bit(self.ienable)?;
        encoder.write_bits(
            u8::from(self.encoder_mode),
            encoder.unit().encoder_mode_width(),
        )?;
        encoder.encode(&self.qual_status)?;
        encoder.encode(&self.ioptions)?;
        encoder.write_bit(self.denable)?;
        if self.denable {
            encoder.write_bit(self.dloss)?;
            encoder.encode(&self.doptions)?;
        }
        Ok(())
    }
}

/// Representation of a change to the filter qualification
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub enum QualStatus {
    /// No change to filter qualification.
    #[default]
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

impl<U> Encode<'_, U> for QualStatus {
    fn encode(&self, encoder: &mut Encoder<U>) -> Result<(), Error> {
        let value: u8 = match self {
            Self::NoChange => 0b00,
            Self::EndedRep => 0b01,
            Self::TraceLost => 0b10,
            Self::EndedNtr => 0b11,
        };
        encoder.write_bits(value, 2)
    }
}

/// Mode the encoder is operating in
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub enum EncoderMode {
    #[default]
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

impl From<EncoderMode> for u8 {
    fn from(mode: EncoderMode) -> Self {
        match mode {
            EncoderMode::BranchTrace => 0,
        }
    }
}
