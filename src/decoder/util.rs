// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Utilities for decoding specific items of packets/payloads

use crate::types::branch;

use super::{Decode, Decoder, Error};

/// Read an address as `u64`
///
/// Read an address as an `u64`, honouring the address width and lsb offset
/// specified in the `decoder`'s protocol configuration. Since it is read as an
/// `u64`, it is not sign extended.
pub fn read_address<U>(decoder: &mut Decoder<U>) -> Result<u64, Error> {
    let width = decoder.proto_conf.iaddress_width_p - decoder.proto_conf.iaddress_lsb_p;
    decoder
        .read_bits::<u64>(width)
        .map(|v| v << decoder.proto_conf.iaddress_lsb_p)
}

/// Read the `irreport` and `irdepth` fields
///
/// This fn reads the `irreport` and `irdepth` fields. The former is read
/// differentially, and if the result is `true` this fn returns `irdepth`.
/// Otherwise, `None` is returned.
pub fn read_implicit_return<U>(decoder: &mut Decoder<U>) -> Result<Option<usize>, Error> {
    let depth_len = decoder.proto_conf.return_stack_size_p
        + decoder.proto_conf.call_counter_size_p
        + (if decoder.proto_conf.return_stack_size_p > 0 {
            1
        } else {
            0
        });
    // We intentionally read both the `irreport` and `irdepth` field
    // unconditionally in order to keep the overall width read constant.
    let report = decoder.read_differential_bit()?;
    let depth = decoder.read_bits(depth_len)?;

    Ok(report.then_some(depth))
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
        let length = core::iter::successors(Some(31), |l| (*l > 0).then_some(l >> 1))
            .take_while(|l| *l >= self.0)
            .last()
            .expect("Could not determine length");
        let mut map = decoder.read_bits(length)?;
        map &= !0u64.checked_shl(self.0.into()).unwrap_or_default();
        Ok(branch::Map::new(self.0, map))
    }

    /// Count for a full branch map
    pub const FULL: Self = Self(31);
}

impl<U> Decode<U> for BranchCount {
    fn decode(decoder: &mut Decoder<U>) -> Result<Self, Error> {
        decoder.read_bits(5).map(Self)
    }
}
