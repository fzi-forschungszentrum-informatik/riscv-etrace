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
