// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Trace unit implementation specific definitions and utilities
//!
//! This module provides traits for capturing some specifics of trace unit
//! implementations not captured by [`config::Parameters`], as well as
//! implementations of those traits.

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
use core::fmt;

use crate::config;

use super::decoder::{Decode, Decoder};
use super::encoder::{Encode, Encoder};
use super::error::Error;

use config::AddressMode;

/// Specifics about a trace unit implementation
pub trait Unit<U = Self> {
    /// Instruction trace options
    type IOptions: IOptions + 'static;

    /// Data trace options
    type DOptions: 'static;

    /// Width of the encoder mode field
    fn encoder_mode_width(&self) -> u8;

    /// Decode instruction trace options
    fn decode_ioptions(decoder: &mut Decoder<U>) -> Result<Self::IOptions, Error>;

    /// Decode data trace options
    fn decode_doptions(decoder: &mut Decoder<U>) -> Result<Self::DOptions, Error>;

    /// Create a [`Plug`] for this unit
    #[cfg(feature = "alloc")]
    fn as_plug(&self) -> Plug
    where
        Self: Unit<Plug> + Sized,
        <Self as Unit<Plug>>::IOptions: fmt::Debug,
        <Self as Unit<Plug>>::DOptions: fmt::Debug,
    {
        Plug::new(self)
    }
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

#[cfg(feature = "alloc")]
impl<T: IOptions + ?Sized> IOptions for Box<T> {
    fn address_mode(&self) -> Option<AddressMode> {
        T::address_mode(self.as_ref())
    }

    fn sequentially_inferred_jumps(&self) -> Option<bool> {
        T::sequentially_inferred_jumps(self.as_ref())
    }

    fn implicit_return(&self) -> Option<bool> {
        T::implicit_return(self.as_ref())
    }

    fn implicit_exception(&self) -> Option<bool> {
        T::implicit_exception(self.as_ref())
    }

    fn branch_prediction(&self) -> Option<bool> {
        T::branch_prediction(self.as_ref())
    }

    fn jump_target_cache(&self) -> Option<bool> {
        T::jump_target_cache(self.as_ref())
    }
}

/// An [`IOptions`] that is [`Debug`][fmt::Debug]
pub trait DebugIOptions: IOptions + fmt::Debug {}

impl<T: IOptions + fmt::Debug> DebugIOptions for T {}

/// Reference trace [`Unit`]
///
/// This unit is used in the reference flow (in the form of a model).
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct Reference;

impl<U> Unit<U> for Reference {
    type IOptions = ReferenceIOptions;
    type DOptions = ReferenceDOptions;

    fn encoder_mode_width(&self) -> u8 {
        1
    }

    fn decode_ioptions(decoder: &mut Decoder<U>) -> Result<Self::IOptions, Error> {
        Decode::decode(decoder)
    }

    fn decode_doptions(decoder: &mut Decoder<U>) -> Result<Self::DOptions, Error> {
        Decode::decode(decoder)
    }
}

/// [`IOptions`] for the [`Reference`] [`Unit`]
#[derive(Copy, Clone, Default, Debug, PartialEq)]
pub struct ReferenceIOptions {
    pub implicit_return: bool,
    pub implicit_exception: bool,
    pub full_address: bool,
    pub jump_target_cache: bool,
    pub branch_prediction: bool,
}

impl<U> Decode<'_, '_, U> for ReferenceIOptions {
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

impl<U> Encode<'_, U> for ReferenceIOptions {
    fn encode(&self, encoder: &mut Encoder<U>) -> Result<(), Error> {
        encoder.write_bit(self.implicit_return)?;
        encoder.write_bit(self.implicit_exception)?;
        encoder.write_bit(self.full_address)?;
        encoder.write_bit(self.jump_target_cache)?;
        encoder.write_bit(self.branch_prediction)
    }
}

impl IOptions for ReferenceIOptions {
    fn address_mode(&self) -> Option<AddressMode> {
        Some(AddressMode::from_full(self.full_address))
    }

    fn implicit_return(&self) -> Option<bool> {
        Some(self.implicit_return)
    }

    fn implicit_exception(&self) -> Option<bool> {
        Some(self.implicit_exception)
    }

    fn branch_prediction(&self) -> Option<bool> {
        Some(self.branch_prediction)
    }

    fn jump_target_cache(&self) -> Option<bool> {
        Some(self.jump_target_cache)
    }
}

/// DOptions for the [`Reference`] [`Unit`]
#[derive(Copy, Clone, Default, Debug, PartialEq)]
pub struct ReferenceDOptions {
    pub no_address: bool,
    pub no_data: bool,
    pub full_address: bool,
    pub full_data: bool,
}

impl<U> Decode<'_, '_, U> for ReferenceDOptions {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        let no_address = decoder.read_bit()?;
        let no_data = decoder.read_bit()?;
        let full_address = decoder.read_bit()?;
        let full_data = decoder.read_bit()?;
        Ok(Self {
            no_address,
            no_data,
            full_address,
            full_data,
        })
    }
}

impl<U> Encode<'_, U> for ReferenceDOptions {
    fn encode(&self, encoder: &mut Encoder<U>) -> Result<(), Error> {
        encoder.write_bit(self.no_address)?;
        encoder.write_bit(self.no_data)?;
        encoder.write_bit(self.full_address)?;
        encoder.write_bit(self.full_data)
    }
}

/// PULP trace [`Unit`]
///
/// Supports the [PULP rv tracer](https://github.com/pulp-platform/rv_tracer)
/// and compatible trace units.
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct PULP;

impl<U> Unit<U> for PULP {
    type IOptions = PULPIOptions;
    type DOptions = NoOptions;

    fn encoder_mode_width(&self) -> u8 {
        1
    }

    fn decode_ioptions(decoder: &mut Decoder<U>) -> Result<Self::IOptions, Error> {
        Decode::decode(decoder)
    }

    fn decode_doptions(decoder: &mut Decoder<U>) -> Result<Self::DOptions, Error> {
        Decode::decode(decoder)
    }
}

/// [`IOptions`] for the [`PULP`] [`Unit`]
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct PULPIOptions {
    pub delta_address: bool,
    pub full_address: bool,
    pub implicit_exception: bool,
    pub sijump: bool,
    pub implicit_return: bool,
    pub branch_prediction: bool,
    pub jump_target_cache: bool,
}

impl<U> Decode<'_, '_, U> for PULPIOptions {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        let jump_target_cache = decoder.read_bit()?;
        let branch_prediction = decoder.read_bit()?;
        let implicit_return = decoder.read_bit()?;
        let sijump = decoder.read_bit()?;
        let implicit_exception = decoder.read_bit()?;
        let full_address = decoder.read_bit()?;
        let delta_address = decoder.read_bit()?;
        Ok(Self {
            delta_address,
            full_address,
            implicit_exception,
            sijump,
            implicit_return,
            branch_prediction,
            jump_target_cache,
        })
    }
}

impl<U> Encode<'_, U> for PULPIOptions {
    fn encode(&self, encoder: &mut Encoder<U>) -> Result<(), Error> {
        encoder.write_bit(self.jump_target_cache)?;
        encoder.write_bit(self.branch_prediction)?;
        encoder.write_bit(self.implicit_return)?;
        encoder.write_bit(self.sijump)?;
        encoder.write_bit(self.implicit_exception)?;
        encoder.write_bit(self.full_address)?;
        encoder.write_bit(self.delta_address)
    }
}

impl IOptions for PULPIOptions {
    fn address_mode(&self) -> Option<AddressMode> {
        match (self.delta_address, self.full_address) {
            (true, false) => Some(AddressMode::Delta),
            (false, true) => Some(AddressMode::Full),
            _ => None,
        }
    }

    fn sequentially_inferred_jumps(&self) -> Option<bool> {
        Some(self.sijump)
    }

    fn implicit_return(&self) -> Option<bool> {
        Some(self.implicit_return)
    }

    fn implicit_exception(&self) -> Option<bool> {
        Some(self.implicit_exception)
    }

    fn branch_prediction(&self) -> Option<bool> {
        Some(self.branch_prediction)
    }

    fn jump_target_cache(&self) -> Option<bool> {
        Some(self.jump_target_cache)
    }
}

/// A [`Unit`] allowing plugging any [`Unit`] into a [`Decoder`]
///
/// [`Decoder`] is generic over its [`Unit`], and may thus be constructed with
/// any [`Unit`]. However , this choice is reflected in the [`Decoder`]'s type.
/// This helper allows erasing the type of the specific [`Unit`] used, serving
/// as a "plug" for arbitrary [`Unit`]s.
#[cfg(feature = "alloc")]
#[allow(clippy::type_complexity)]
#[derive(Copy, Clone, Debug)]
pub struct Plug {
    encoder_mode_width: u8,
    decode_ioptions: fn(&mut Decoder<Self>) -> Result<Box<dyn DebugIOptions>, Error>,
    decode_doptions: fn(&mut Decoder<Self>) -> Result<Box<dyn fmt::Debug>, Error>,
}

#[cfg(feature = "alloc")]
impl Plug {
    /// Create a new plug for the given [`Unit`]
    pub fn new<U>(inner: &U) -> Self
    where
        U: Unit<Self>,
        U::IOptions: fmt::Debug,
        U::DOptions: fmt::Debug,
    {
        fn decode_ioptions<U>(decoder: &mut Decoder<Plug>) -> Result<Box<dyn DebugIOptions>, Error>
        where
            U: Unit<Plug>,
            U::IOptions: fmt::Debug,
        {
            U::decode_ioptions(decoder).map(|r| -> Box<dyn DebugIOptions> { Box::new(r) })
        }

        fn decode_doptions<U>(decoder: &mut Decoder<Plug>) -> Result<Box<dyn fmt::Debug>, Error>
        where
            U: Unit<Plug>,
            U::DOptions: fmt::Debug,
        {
            U::decode_doptions(decoder).map(|r| -> Box<dyn fmt::Debug> { Box::new(r) })
        }

        Self {
            encoder_mode_width: inner.encoder_mode_width(),
            decode_ioptions: decode_ioptions::<U>,
            decode_doptions: decode_doptions::<U>,
        }
    }
}

#[cfg(feature = "alloc")]
impl Default for Plug {
    fn default() -> Self {
        Self::new(&Reference)
    }
}

#[cfg(feature = "alloc")]
impl Unit for Plug {
    type IOptions = Box<dyn DebugIOptions>;
    type DOptions = Box<dyn fmt::Debug>;

    fn encoder_mode_width(&self) -> u8 {
        self.encoder_mode_width
    }

    fn decode_ioptions(decoder: &mut Decoder<Self>) -> Result<Self::IOptions, Error> {
        (decoder.unit().decode_ioptions)(decoder)
    }

    fn decode_doptions(decoder: &mut Decoder<Self>) -> Result<Self::DOptions, Error> {
        (decoder.unit().decode_doptions)(decoder)
    }
}

/// List of [`Plug`] constructors for all [`Unit`]s provided by this library
#[cfg(feature = "alloc")]
#[allow(clippy::type_complexity)]
pub const PLUGS: &[(&str, fn() -> Plug)] = &[
    ("reference", || Plug::new(&Reference)),
    ("pulp", || Plug::new(&PULP)),
];

/// Type representing an empty set, zero-bit wide set of options
#[derive(Copy, Clone, Debug, Default)]
pub struct NoOptions;

impl<U> Decode<'_, '_, U> for NoOptions {
    fn decode(_decoder: &mut Decoder<U>) -> Result<Self, Error> {
        Ok(Self)
    }
}

impl<U> Encode<'_, U> for NoOptions {
    fn encode(&self, _encoder: &mut Encoder<U>) -> Result<(), Error> {
        Ok(())
    }
}

impl IOptions for NoOptions {}
