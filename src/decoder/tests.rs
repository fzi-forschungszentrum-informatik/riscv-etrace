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
    let mut decoder = Decoder::default();
    decoder.reset();
    // testing for bit position
    assert_eq!(decoder.read(6, &buffer).unwrap(), 0b011111);
    assert_eq!(decoder.bit_pos, 6);
    assert_eq!(decoder.read(2, &buffer).unwrap(), 0b01);
    assert_eq!(decoder.bit_pos, 8);
    assert_eq!(decoder.read(6, &buffer).unwrap(), 0b011111);
    assert_eq!(decoder.bit_pos, 14);
    // read over byte boundary
    assert_eq!(decoder.read(10, &buffer).unwrap(), 0b1001001001);
    assert_eq!(decoder.bit_pos, 24);
    assert_eq!(decoder.read(62, &buffer).unwrap(), 0x3FFF_F0F0_F0F0_F0F1);
    assert_eq!(decoder.bit_pos, 86);
    assert_eq!(decoder.read(64, &buffer).unwrap(), 0xC000_0000_0000_0005);
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
    let mut decoder = Decoder::default();
    decoder.reset();
    assert_eq!(decoder.read(1, &buffer).unwrap(), 0);
    assert_eq!(decoder.read(64, &buffer).unwrap() as i64, -24);
}

#[test]
fn read_entire_buffer() {
    let buffer = [255; DEFAULT_PACKET_BUFFER_LEN];
    let mut decoder = Decoder::default();
    decoder.reset();
    assert_eq!(decoder.read(64, &buffer).unwrap(), u64::MAX);
    assert_eq!(decoder.read(64, &buffer).unwrap(), u64::MAX);
    assert_eq!(decoder.read(64, &buffer).unwrap(), u64::MAX);
    assert_eq!(decoder.read(64, &buffer).unwrap(), u64::MAX);
}

#[test]
fn read_bool_bits() {
    let buffer = [0b0101_0101; DEFAULT_PACKET_BUFFER_LEN];
    let mut decoder = Decoder::default();
    decoder.reset();
    assert!(decoder.read_bit(&buffer).unwrap());
    assert!(!decoder.read_bit(&buffer).unwrap());
    assert!(decoder.read_bit(&buffer).unwrap());
    assert!(!decoder.read_bit(&buffer).unwrap());
    assert!(decoder.read_bit(&buffer).unwrap());
    assert!(!decoder.read_bit(&buffer).unwrap());
    assert!(decoder.read_bit(&buffer).unwrap());
    assert!(!decoder.read_bit(&buffer).unwrap());
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
    let mut decoder = Decoder::default();
    decoder.reset();
    assert_eq!(decoder.read(6, &buffer).unwrap(), 0);
    // Modelled after read_address call with iaddress_width_p: 64 and iaddress_lsb_p: 1
    assert_eq!((decoder.read(63, &buffer).unwrap() << 1), -248i64 as u64);
}

const DEFAULT_PACKET_BUFFER_LEN: usize = 32;
