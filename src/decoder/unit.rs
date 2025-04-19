// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Trace unit implementation specific definitions and utilities

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
