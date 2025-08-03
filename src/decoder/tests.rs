// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
use super::*;

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

#[test]
fn extension_jti_1() {
    let protocol_config = Default::default();

    let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
    buffer[0] = 0b00000000;
    buffer[1] = 0b0_11111_11;
    buffer[2] = 0b00000_101;

    let mut decoder = Builder::new()
        .with_params(&config::Parameters {
            cache_size_p: 10,
            ..protocol_config
        })
        .build(&buffer);

    let jti_long = payload::JumpTargetIndex::decode(&mut decoder).unwrap();
    assert_eq!(jti_long.index, 768);
    assert_eq!(jti_long.branch_map.count(), 31);
    assert_eq!(jti_long.branch_map.raw_map(), 10);
}

#[test]
fn extension_jti_2() {
    let protocol_config = Default::default();

    let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
    buffer[0] = 0b11111111;
    buffer[1] = 0b00000011;
    let mut decoder = Builder::new()
        .with_params(&config::Parameters {
            cache_size_p: 10,
            ..protocol_config
        })
        .build(&buffer);

    let jti_short = payload::JumpTargetIndex::decode(&mut decoder).unwrap();
    assert_eq!(jti_short.index, 1023);
    assert_eq!(jti_short.branch_map, Default::default());
}

#[test]
fn branch() {
    let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
    buffer[0] = 0b010_00111;
    buffer[1] = 0b0000_1011;
    let mut decoder = Builder::new().build(&buffer);
    let branch = payload::Branch::decode(&mut decoder).unwrap();
    assert_eq!(branch.branch_map.count(), 7);
    assert_eq!(branch.branch_map.raw_map(), 0b1011_010);
    assert_eq!(
        branch.address,
        Some(AddressInfo {
            address: 0,
            notify: false,
            updiscon: false,
            irdepth: None,
        })
    );
}

#[test]
fn branch_with_zero_branches() {
    let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
    buffer[0] = 0b000_00000;
    buffer[1] = 0b100;
    let mut decoder = Builder::new().build(&buffer);
    let branch_no_addr = payload::Branch::decode(&mut decoder).unwrap();
    assert_eq!(branch_no_addr.branch_map.count(), 31);
    assert_eq!(branch_no_addr.branch_map.raw_map(), 32);
    assert_eq!(branch_no_addr.address, None);
}

#[test]
fn address_absolute() {
    let protocol_config = Default::default();

    let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
    buffer[0] = 0b0000_0001;
    buffer[7] = 0b11_000000;
    let mut decoder = Builder::new()
        .with_params(&config::Parameters {
            // Changed address width and lsb, so that the entire
            // packet aligns with 64 bit
            iaddress_width_p: 64.try_into().unwrap(),
            iaddress_lsb_p: 2.try_into().unwrap(),
            ..protocol_config
        })
        .build(&buffer);

    let addr = AddressInfo::decode(&mut decoder).unwrap();
    assert_eq!(addr.address, 4);
    assert!(addr.notify);
    assert!(!addr.updiscon);
}

#[test]
fn address_differential() {
    let protocol_config = Default::default();

    let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
    buffer[0] = 0b0000_0001;
    buffer[7] = 0b10_000000;
    let mut decoder = Builder::new()
        .with_params(&config::Parameters {
            // Changed address width and lsb, so that the entire
            // packet aligns with 64 bit
            iaddress_width_p: 64.try_into().unwrap(),
            iaddress_lsb_p: 2.try_into().unwrap(),
            ..protocol_config
        })
        .build(&buffer);

    let diff_addr = AddressInfo::decode(&mut decoder).unwrap();
    assert_eq!(diff_addr.address, 4);
    assert!(!diff_addr.notify);
    assert!(diff_addr.updiscon);
}

#[test]
fn synchronization_start() {
    use crate::types::Privilege;

    let protocol_config = Default::default();

    let buffer = [255; DEFAULT_PACKET_BUFFER_LEN];
    let mut decoder = Builder::new()
        .with_params(&config::Parameters {
            iaddress_width_p: 64.try_into().unwrap(),
            iaddress_lsb_p: 1.try_into().unwrap(),
            ..protocol_config
        })
        .build(&buffer);
    let sync_start = sync::Start::decode(&mut decoder).unwrap();
    assert!(sync_start.branch);
    assert_eq!(sync_start.ctx.privilege, Privilege::Machine);
    assert_eq!(sync_start.address, 0xffff_ffff_ffff_fffe);
}

const DEFAULT_PACKET_BUFFER_LEN: usize = 32;
