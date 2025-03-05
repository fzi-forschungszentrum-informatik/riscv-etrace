// Copyright (C) 2024 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
use super::*;

#[test]
fn read_u64() {
    let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
    buffer[0] = 0b01_011111;
    buffer[1] = 0b01_011111;
    buffer[2] = 0b10010010;
    buffer[3] = 0xF1;
    buffer[4] = 0xF0;
    buffer[5] = 0xF0;
    buffer[6] = 0xF0;
    buffer[7] = 0xF0;
    buffer[8] = 0xF0;
    buffer[9] = 0xFF;
    buffer[10] = 0b01_111111;
    buffer[11] = 0b1;
    // ...
    buffer[18] = 0b11_110000;
    let mut decoder = Decoder::default().with_data(&buffer);
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
    let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
    buffer[0] = 0b1101000_0;
    buffer[1] = 0xFF;
    buffer[2] = 0xFF;
    buffer[3] = 0xFF;
    buffer[4] = 0xFF;
    buffer[5] = 0xFF;
    buffer[6] = 0xFF;
    buffer[7] = 0xFF;
    buffer[8] = 0b1;
    let mut decoder = Decoder::default().with_data(&buffer);
    assert_eq!(decoder.read_bits(1), Ok(0i64));
    assert_eq!(decoder.read_bits(64), Ok(-24i64));
}

#[test]
fn read_entire_buffer() {
    let buffer = [255; DEFAULT_PACKET_BUFFER_LEN];
    let mut decoder = Decoder::default().with_data(&buffer);
    assert_eq!(decoder.read_bits(64), Ok(u64::MAX));
    assert_eq!(decoder.read_bits(64), Ok(u64::MAX));
    assert_eq!(decoder.read_bits(64), Ok(u64::MAX));
    assert_eq!(decoder.read_bits(64), Ok(u64::MAX));
}

#[test]
fn read_bool_bits() {
    let buffer = [0b0101_0101; DEFAULT_PACKET_BUFFER_LEN];
    let mut decoder = Decoder::default().with_data(&buffer);
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
    let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
    buffer[0] = 0b00_000000;
    buffer[1] = 0xE1;
    buffer[2] = 0xFF;
    buffer[3] = 0xFF;
    buffer[4] = 0xFF;
    buffer[5] = 0xFF;
    buffer[6] = 0xFF;
    buffer[7] = 0xFF;
    buffer[8] = 0b00_111111;
    let mut decoder = Decoder::default().with_data(&buffer);
    assert_eq!(decoder.read_bits(6), Ok(0i64));
    // Modelled after read_address call with iaddress_width_p: 64 and iaddress_lsb_p: 1
    assert_eq!(decoder.read_bits(63), Ok(-124i64));
}

// `format` related tests

#[test]
fn sync() {
    use format::Sync;

    let buffer = [0b10_01_00_11_u8; 32];
    let mut decoder = Decoder::default().with_data(&buffer);
    assert_eq!(Sync::decode(&mut decoder), Ok(Sync::Support));
    assert_eq!(Sync::decode(&mut decoder), Ok(Sync::Start));
    assert_eq!(Sync::decode(&mut decoder), Ok(Sync::Trap));
    assert_eq!(Sync::decode(&mut decoder), Ok(Sync::Context));
}

#[test]
fn extension() {
    use format::Ext;

    let buffer = [0b0010u8; 32];
    let mut decoder = Decoder::default().with_data(&buffer);
    assert_eq!(Ext::decode(&mut decoder), Ok(Ext::BranchCount));
    assert_eq!(Ext::decode(&mut decoder), Ok(Ext::JumpTargetIndex));
}

#[test]
fn format() {
    use format::{Ext, Format, Sync};

    let mut buffer = [0u8; 32];
    buffer[0] = 0b1_10_01_100;
    buffer[1] = 0b00000_011;
    let mut decoder = Decoder::default().with_data(&buffer);
    assert_eq!(
        Format::decode(&mut decoder),
        Ok(Format::Ext(Ext::JumpTargetIndex)),
    );
    assert_eq!(Format::decode(&mut decoder), Ok(Format::Branch));
    assert_eq!(Format::decode(&mut decoder), Ok(Format::Addr));
    assert_eq!(Format::decode(&mut decoder), Ok(Format::Sync(Sync::Trap)));
}

// `payload` related tests

#[test]
fn extension_jti() {
    let protocol_config = ProtocolConfiguration::default();
    let decoder_config = DecoderConfiguration::default();

    let cache_size_p_override = 10;
    let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
    buffer[0] = 0b00000000;
    buffer[1] = 0b0_11111_11;
    buffer[2] = 0b00000_101;
    // ...
    buffer[5] = 0b11_000000;
    buffer[6] = 0b11111111;
    let mut decoder = Decoder::new(
        ProtocolConfiguration {
            cache_size_p: cache_size_p_override,
            ..protocol_config
        },
        decoder_config,
    )
    .with_data(&buffer);

    let jti_long = JumpTargetIndex::decode(&mut decoder).unwrap();
    assert_eq!(jti_long.index, 768);
    assert_eq!(jti_long.branches, 31);
    assert_eq!(jti_long.branch_map, Some(10));
    let jti_short = JumpTargetIndex::decode(&mut decoder).unwrap();
    assert_eq!(jti_short.index, 1023);
    assert_eq!(jti_short.branches, 0);
    assert_eq!(jti_short.branch_map, None);
}

#[test]
fn branch() {
    let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
    buffer[0] = 0b010_00111;
    buffer[1] = 0b0000_1011;
    let mut decoder = Decoder::default().with_data(&buffer);
    let branch = Branch::decode(&mut decoder).unwrap();
    assert_eq!(branch.branches, 7);
    assert_eq!(branch.branch_map, 0b1011_010);
    assert_eq!(
        branch.address,
        Some(AddressInfo {
            address: 0,
            notify: false,
            updiscon: false,
        })
    );
}

#[test]
fn branch_with_zero_branches() {
    let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
    buffer[0] = 0b000_00000;
    buffer[1] = 0b100;
    let mut decoder = Decoder::default().with_data(&buffer);
    let branch_no_addr = Branch::decode(&mut decoder).unwrap();
    assert_eq!(branch_no_addr.branches, 0);
    assert_eq!(branch_no_addr.branch_map, 32);
    assert_eq!(branch_no_addr.address, None);
}

#[test]
fn address() {
    let protocol_config = ProtocolConfiguration::default();
    let decoder_config = DecoderConfiguration::default();

    let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
    buffer[0] = 0b0000_0001;
    buffer[7] = 0b11_000000;
    // test differential addr with second address
    buffer[8] = 0b0000_0001;
    buffer[15] = 0b10_000000;
    let mut decoder = Decoder::new(
        ProtocolConfiguration {
            // Changed address width and lsb, so that the entire
            // packet aligns with 64 bit
            iaddress_width_p: 64,
            iaddress_lsb_p: 2,
            ..protocol_config
        },
        decoder_config,
    )
    .with_data(&buffer);
    let addr = AddressInfo::decode(&mut decoder).unwrap();
    assert_eq!(addr.address, 4);
    assert!(addr.notify);
    assert!(!addr.updiscon);

    // differential address
    let diff_addr = AddressInfo::decode(&mut decoder).unwrap();
    assert_eq!(diff_addr.address, 4);
    assert!(!diff_addr.notify);
    assert!(diff_addr.updiscon);
}

#[test]
fn synchronization_start() {
    let protocol_config = ProtocolConfiguration::default();
    let decoder_config = DecoderConfiguration::default();

    let buffer = [255; DEFAULT_PACKET_BUFFER_LEN];
    let mut decoder = Decoder::new(
        ProtocolConfiguration {
            iaddress_width_p: 64,
            iaddress_lsb_p: 0,
            ..protocol_config
        },
        decoder_config,
    )
    .with_data(&buffer);
    let sync_start = Start::decode(&mut decoder).unwrap();
    assert!(sync_start.branch);
    assert_eq!(sync_start.ctx.privilege, Privilege::Machine);
    assert_eq!(sync_start.address, u64::MAX);
}

const DEFAULT_PACKET_BUFFER_LEN: usize = 32;
