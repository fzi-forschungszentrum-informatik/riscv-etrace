// Copyright (C) 2025, 2026 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Tests for extraction of [`Instruction`]s or instruction [`Bits`]
#![allow(clippy::unusual_byte_groupings)]

use super::*;

// Bits extraction tests
macro_rules! bits_exract_test {
    ($name:ident, $bytes:expr, $expected:expr, $remaining:expr) => {
        #[test]
        fn $name() {
            let data = $bytes;
            assert_eq!(
                Bits::extract(&data),
                Some(($expected, $remaining.as_slice()))
            );
        }
    };
}

bits_exract_test!(
    extract_16,
    [0x14, 0x41, 0x11, 0x05],
    Bits::Bit16(0x4114),
    [0x11, 0x05]
);
bits_exract_test!(
    extract_32,
    [0x97, 0x06, 0x00, 0x00, 0x93, 0x86, 0x86, 0x05],
    Bits::Bit32(0x00000697),
    [0x93, 0x86, 0x86, 0x05]
);
bits_exract_test!(
    extract_48,
    [0x5F, 0x36, 0x98, 0x00, 0x45, 0xF1, 0x20, 0x37],
    Bits::Bit48(0xF1450098365F),
    [0x20, 0x37]
);
bits_exract_test!(
    extract_64,
    [0xBF, 0x2F, 0x15, 0x46, 0x52, 0x8C, 0x84, 0x23, 0xFE, 0x4B],
    Bits::Bit64(0x23848C5246152FBF),
    [0xFE, 0x4B]
);

#[test]
fn bits_extract_none() {
    let data = [0xFF, 0x82, 0xCA, 0xF5, 0xEF];
    assert_eq!(Bits::extract(&data), None,)
}

#[test]
fn bits_extract_size() {
    for i in u8::MIN..=u8::MAX {
        let data = [i, 0, 0, 0, 0, 0, 0, 0];
        let Some((bits, rest)) = Bits::extract(&data) else {
            continue;
        };
        let size = data.len() - rest.len();
        assert_eq!(u64::from(bits.size()), size.try_into().unwrap());
    }
}

#[test]
fn extract_test() {
    // auipc imm 20 bits 31:12; 11:7 rd; 6:0 op: 0010111; immediate: 0001_0100_0100_0101_1100,  rd: 10000
    let data: u32 = 0b_00010100010001011100_10000_0010111; // imm; rd; op
    let bytes_reverse = data.to_le_bytes();
    assert_eq!(bytes_reverse, [0x17, 0xC8, 0x45, 0x14]);

    // extract instruction
    let (instruction, remaining) = Instruction::<Option<Kind>>::extract(&bytes_reverse, &Rv32I)
        .expect("Cannot extract instruction from data stream!");

    // Ensure Instruction Size and Kind are correctly extracted
    let size = instruction.size;
    let info = instruction.info.expect("Instruction is unknown");
    assert_eq!(size, Size::Normal);
    assert_eq!(remaining, []);
    assert_eq!(info, Kind::new_auipc(16, 0b0001_0100_0100_0101_1100 << 12));
}
