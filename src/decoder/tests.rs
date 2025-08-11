// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
use super::*;

use crate::types::{self, branch};

use payload::AddressInfo;

macro_rules! bitstream_test {
    ($n:ident, $b:literal, $d:expr) => {
        #[test]
        fn $n() {
            let mut decoder = Builder::new().build($b);
            assert_eq!(Decode::decode(&mut decoder), Ok($d));
        }
    };
    ($n:ident, $b:literal, $d:expr, $( $k:ident : $v:expr ),*) => {
        #[test]
        fn $n() {
            let mut decoder = Builder::new()
                .with_params(&config::Parameters {
                    $($k: $v,)*
                    ..Default::default()
                })
                .build($b);
            assert_eq!(Decode::decode(&mut decoder), Ok($d));
        }
    };
}

#[test]
fn read_u64() {
    let mut decoder = Builder::new()
        .build(b"\x5f\x5f\x92\xf1\xf0\xf0\xf0\xf0\xf0\xff\x7f\x01\x00\x00\x00\x00\x00\x00\xf0");
    // testing for bit position
    assert_eq!(decoder.read_bits(6), Ok(0b011111u64));
    assert_eq!(decoder.bit_pos, 6);
    assert_eq!(decoder.read_bits(2), Ok(0b01u64));
    assert_eq!(decoder.bit_pos, 8);
    assert_eq!(decoder.read_bits(6), Ok(0b011111u64));
    assert_eq!(decoder.bit_pos, 14);
    // read over byte boundary
    assert_eq!(decoder.read_bits(10), Ok(0b1001001001u64));
    assert_eq!(decoder.bit_pos, 24);
    assert_eq!(decoder.read_bits(62), Ok(0x3FFF_F0F0_F0F0_F0F1u64));
    assert_eq!(decoder.bit_pos, 86);
    assert_eq!(decoder.read_bits(64), Ok(0xC000_0000_0000_0005u64));
    assert_eq!(decoder.bit_pos, 150);
}

#[test]
fn read_i64() {
    let mut decoder = Builder::new().build(b"\xd0\xff\xff\xff\xff\xff\xff\xff\x01");
    assert_eq!(decoder.read_bits(1), Ok(0i64));
    assert_eq!(decoder.read_bits(64), Ok(-24i64));
}

#[test]
fn read_entire_buffer() {
    let mut decoder = Builder::new().build(b"\xff");
    assert_eq!(decoder.read_bits(64), Ok(u64::MAX));
    assert_eq!(decoder.read_bits(64), Ok(u64::MAX));
    assert_eq!(decoder.read_bits(64), Ok(u64::MAX));
    assert_eq!(decoder.read_bits(64), Ok(u64::MAX));
}

#[test]
fn read_bool_bits() {
    let mut decoder = Builder::new().build(b"\x55");
    assert_eq!(decoder.read_bit(), Ok(true));
    assert_eq!(decoder.read_bit(), Ok(false));
    assert_eq!(decoder.read_bit(), Ok(true));
    assert_eq!(decoder.read_bit(), Ok(false));
    assert_eq!(decoder.read_bit(), Ok(true));
    assert_eq!(decoder.read_bit(), Ok(false));
    assert_eq!(decoder.read_bit(), Ok(true));
    assert_eq!(decoder.read_bit(), Ok(false));
}

#[test]
fn missing_msb_shift_is_correct() {
    let mut decoder = Builder::new().build(b"\x00\xe1\xff\xff\xff\xff\xff\xff\x3f");
    assert_eq!(decoder.read_bits(6), Ok(0i64));
    // Modelled after read_address call with iaddress_width_p: 64 and iaddress_lsb_p: 1
    assert_eq!(decoder.read_bits(63), Ok(-124i64));
}

// `format` related tests
bitstream_test!(sync_support, b"\x03", format::Sync::Support);
bitstream_test!(sync_start, b"\x00", format::Sync::Start);
bitstream_test!(sync_trap, b"\x01", format::Sync::Trap);
bitstream_test!(sync_ctx, b"\x02", format::Sync::Context);
bitstream_test!(fmt_ex_branch_count, b"\x00", format::Ext::BranchCount, f0s_width_p: 1);
bitstream_test!(fmt_ex_jti, b"\x01", format::Ext::JumpTargetIndex, f0s_width_p: 1);
bitstream_test!(fmt_1, b"\x04", format::Format::Ext(format::Ext::JumpTargetIndex), f0s_width_p: 1);
bitstream_test!(fmt_2, b"\x01", format::Format::Branch, f0s_width_p: 1);
bitstream_test!(fmt_3, b"\x02", format::Format::Addr, f0s_width_p: 1);
bitstream_test!(fmt_4, b"\x07", format::Format::Sync(format::Sync::Trap), f0s_width_p: 1);

// `payload` related tests
bitstream_test!(
    extension_jti_1,
    b"\x00\x7f\x05",
    payload::JumpTargetIndex { index: 768, branch_map: branch::Map::new(31, 10), irdepth: None },
    cache_size_p: 10
);
bitstream_test!(
    extension_jti_2,
    b"\xff\x03",
    payload::JumpTargetIndex { index: 1023, branch_map: Default::default(), irdepth: None },
    cache_size_p: 10
);
bitstream_test!(
    branch,
    b"\x47\x0b",
    payload::Branch {
        branch_map: branch::Map::new(7, 0b1011_010),
        address: Some(AddressInfo { address: 0, notify: false, updiscon: false, irdepth: None }),
    },
    cache_size_p: 10
);
bitstream_test!(
    branch_with_zero_branches,
    b"\x00\x04",
    payload::Branch {
        branch_map: branch::Map::new(31, 32),
        address: None
    }
);
bitstream_test!(
    address_absolute,
    b"\x01\x00\x00\x00\x00\x00\x00\xc0",
    payload::AddressInfo { address: 4, notify: true, updiscon: false, irdepth: None },
    iaddress_width_p: 64.try_into().unwrap(),
    iaddress_lsb_p: 2.try_into().unwrap()

);
bitstream_test!(
    address_differential,
    b"\x01\x00\x00\x00\x00\x00\x00\x80",
    payload::AddressInfo { address: 4, notify: false, updiscon: true, irdepth: None },
    iaddress_width_p: 64.try_into().unwrap(),
    iaddress_lsb_p: 2.try_into().unwrap()

);
bitstream_test!(
    synchronization_start,
    b"\xff",
    sync::Start {
        branch: true,
        ctx: sync::Context { privilege: types::Privilege::Machine, time: None, context: None },
        address: 0xffff_ffff_ffff_fffe,
    },
    iaddress_width_p: 64.try_into().unwrap(),
    iaddress_lsb_p: 1.try_into().unwrap()
);
