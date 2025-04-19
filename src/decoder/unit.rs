// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Trace unit implementation specific definitions and utilities

use super::{Decoder, Error};

/// Specifics about a trace unit implementation
pub trait Unit {
    /// Instruction trace options
    type IOptions;

    /// Width of the encoder mode field
    fn encoder_mode_width(&self) -> u8;

    /// Decode instruction trace options
    fn decode_ioptions(decoder: &mut Decoder) -> Result<Self::IOptions, Error>;
}
