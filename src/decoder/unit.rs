// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Trace unit implementation specific definitions and utilities

use crate::config::AddressMode;

use super::{Decode, Decoder, Error};

/// Specifics about a trace unit implementation
pub trait Unit<U = Self> {
    /// Instruction trace options
    type IOptions;

    /// Width of the encoder mode field
    fn encoder_mode_width(&self) -> u8;

    /// Decode instruction trace options
    fn decode_ioptions(decoder: &mut Decoder<U>) -> Result<Self::IOptions, Error>;
}

/// Instruction trace options that may be communicated via support packets
///
/// This trait features fns that return either [`Some`] value reflecting an
/// option or [`None`] if the type does not contain any information on the
/// specific option.
pub trait IOptions {
    /// Retrieve the encoder's address mode
    fn address_mode(&self) -> Option<AddressMode> {
        None
    }

    /// Retrieve whether the encoder reports sequentially inferable jumps
    ///
    /// Returns `Some(true)` if the encoder signals that it does _not_ report
    /// sequentially inferable jumps and `Some(false)` if it signals that it
    /// _does_ report them.
    fn sequentially_inferred_jumps(&self) -> Option<bool> {
        None
    }

    /// Retrieve whether the encoder reports function return addresses
    ///
    /// Returns `Some(true)` if the encoder signals that it does _not_ report
    /// function return addresses and `Some(false)` if it signals that it _does_
    /// report them.
    fn implicit_return(&self) -> Option<bool> {
        None
    }

    /// Retrieve whether the encoder may omit trap vector addresses
    ///
    /// Returns `Some(true)` if the encoder signals that it omits addresses from
    /// packets reporting traps if that address can be determined from `ecause`.
    /// Returns `Some(false)` if the encoder signals that it always includes the
    /// address.
    fn implicit_exception(&self) -> Option<bool> {
        None
    }

    /// Retrieve whether branch prediction is enabled
    fn branch_prediction(&self) -> Option<bool> {
        None
    }

    /// Retrieve whether jump target caching is enabled
    fn jump_target_cache(&self) -> Option<bool> {
        None
    }
}

/// Reference trace [Unit]
///
/// This unit is used in the reference flow (in the form of a model).
#[derive(Copy, Clone, Debug, Default)]
pub struct Reference;

impl<U> Unit<U> for Reference {
    type IOptions = ReferenceIOptions;

    fn encoder_mode_width(&self) -> u8 {
        1
    }

    fn decode_ioptions(decoder: &mut Decoder<U>) -> Result<Self::IOptions, Error> {
        Decode::decode(decoder)
    }
}

/// IOptions for the [Reference] [Unit]
#[derive(Copy, Clone, Debug)]
pub struct ReferenceIOptions {
    pub implicit_return: bool,
    pub implicit_exception: bool,
    pub full_address: bool,
    pub jump_target_cache: bool,
    pub branch_prediction: bool,
}

impl<U> Decode<U> for ReferenceIOptions {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        let implicit_return = decoder.read_bit()?;
        let implicit_exception = decoder.read_bit()?;
        let full_address = decoder.read_bit()?;
        let jump_target_cache = decoder.read_bit()?;
        let branch_prediction = decoder.read_bit()?;
        Ok(Self {
            implicit_return,
            implicit_exception,
            full_address,
            jump_target_cache,
            branch_prediction,
        })
    }
}
