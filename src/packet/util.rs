// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Utilities for decoding specific items of packets/payloads

use core::ops;

use crate::types::branch;

use super::decoder::{Decode, Decoder};
use super::encoder::{Encode, Encoder};
use super::{truncate, Error};

/// Read an address
///
/// Read an address, honouring the address width and lsb offset specified in the
/// [`Decoder`]'s protocol configuration.
pub fn read_address<U, T>(decoder: &mut Decoder<U>) -> Result<T, Error>
where
    T: From<u8>
        + ops::Shl<u8, Output = T>
        + ops::Shl<usize, Output = T>
        + ops::Shr<usize, Output = T>
        + ops::BitOrAssign<T>
        + truncate::TruncateNum,
{
    let widths = decoder.widths();
    let lsb = widths.iaddress_lsb.get();
    let width = widths.iaddress.get().saturating_sub(lsb);
    decoder.read_bits::<T>(width).map(|v| v << lsb)
}

/// Write an address
///
/// Write an address, honouring the address width and lsb offset specified in the
/// [`Encoder`]'s protocol configuration.
pub fn write_address<B, U, T>(encoder: &mut Encoder<B, U>, address: T) -> Result<(), Error>
where
    B: AsMut<[u8]>,
    T: Copy
        + ops::Shl<usize, Output = T>
        + ops::Shr<usize, Output = T>
        + ops::BitOrAssign<T>
        + truncate::TruncateNum,
{
    let widths = encoder.widths();
    let lsb = widths.iaddress_lsb.get();
    let width = widths.iaddress.get().saturating_sub(lsb);
    encoder.write_bits(address >> lsb.into(), width)
}

/// Read the `irreport` and `irdepth` fields
///
/// This fn reads the `irreport` and `irdepth` fields. The former is read
/// differentially, and if the result is `true` this fn returns `irdepth`.
/// Otherwise, `None` is returned.
pub fn read_implicit_return<U>(decoder: &mut Decoder<U>) -> Result<Option<usize>, Error> {
    // We intentionally read both the `irreport` and `irdepth` field
    // unconditionally in order to keep the overall width read constant.
    let report = decoder.read_differential_bit()?;
    let depth = decoder
        .widths()
        .stack_depth
        .map(|w| decoder.read_bits(w.get()))
        .transpose()?;
    if report {
        Ok(depth)
    } else {
        Ok(None)
    }
}

/// Write the `irreport` and `irdepth` fields
///
/// This fn reads the `irreport` and `irdepth` fields. The former is written
/// differentially, and is `true` if `irdepth` is not `None`.
pub fn write_implicit_return<B: AsMut<[u8]>, U>(
    encoder: &mut Encoder<B, U>,
    irdepth: Option<usize>,
) -> Result<(), Error> {
    encoder.write_differential_bit(irdepth.is_some())?;
    Option::zip(irdepth, encoder.widths().stack_depth)
        .map(|(v, w)| encoder.write_bits(v, w.get()))
        .transpose()?;
    Ok(())
}

/// Utility for decoding branch maps
///
/// Branch maps consist of a count and the map data, wtih a field length derived
/// from the count. This utility allows reading a count, and then reading a
/// [branch::Map], potentially with an altered count.
#[derive(Copy, Clone, Debug)]
pub struct BranchCount(pub u8);

impl BranchCount {
    /// Determine whether this count is zero
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Read a branch map with this count
    pub fn read_branch_map<U>(self, decoder: &mut Decoder<U>) -> Result<branch::Map, Error> {
        let mut map = decoder.read_bits(self.field_length())?;
        map &= !0u32.checked_shl(self.0.into()).unwrap_or_default();
        Ok(branch::Map::new(self.0, map))
    }

    /// Determine the field length
    pub fn field_length(self) -> u8 {
        core::iter::successors(Some(31), |l| (*l > 0).then_some(l >> 1))
            .take_while(|l| *l >= self.0)
            .last()
            .expect("Could not determine length")
    }

    /// Count for a full branch map
    pub const FULL: Self = Self(31);
}

impl<U> Decode<'_, '_, U> for BranchCount {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        decoder.read_bits(5).map(Self)
    }
}

impl<B: AsMut<[u8]>, U> Encode<B, U> for BranchCount {
    fn encode(&self, encoder: &mut Encoder<B, U>) -> Result<(), Error> {
        encoder.write_bits(self.0, 5)
    }
}
