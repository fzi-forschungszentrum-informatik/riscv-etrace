// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Utilities for decoding specific items of packets/payloads

use super::{Decoder, Error};

/// Read an address as `u64`
///
/// Read an address as an `u64`, honouring the address width and lsb offset
/// specified in the `decoder`'s protocol configuration. Since it is read as an
/// `u64`, it is not sign extended.
pub fn read_address(decoder: &mut Decoder) -> Result<u64, Error> {
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
pub fn read_implicit_return(decoder: &mut Decoder) -> Result<Option<usize>, Error> {
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
