// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Instruction decode tests
#![allow(clippy::unusual_byte_groupings)]

use super::*;

macro_rules! decode_test {
    ($s:ident, $n:ident, $l:literal, $k:expr, $bt:expr, $jt:expr, $uj:expr) => {
        #[test]
        fn $n() {
            let insn = $l.try_into().expect("Could not decode");
            let insn = $s.decode_bits(insn).expect("Could not decode");
            assert_eq!(insn, $k);
            assert_eq!(insn.branch_target(), $bt);
            assert_eq!(insn.inferable_jump_target(), $jt);
            assert_eq!(insn.uninferable_jump_target(), $uj);
        }
    };
    ($s:ident, $n:ident, $l:literal, None) => {
        #[test]
        fn $n() {
            let insn = $l.try_into().expect("Could not decode");
            assert_eq!($s.decode_bits(insn), None);
        }
    };
    ($s:ident, $n:ident, $l:literal, $k:expr, b, $t:expr) => {
        decode_test!($s, $n, $l, $k, Some($t), None, None);
    };
    ($s:ident, $n:ident, $l:literal, $k:expr, j, $t:expr) => {
        decode_test!($s, $n, $l, $k, None, Some($t), None);
    };
    ($s:ident, $n:ident, $l:literal, $k:expr, u, $t:expr) => {
        decode_test!($s, $n, $l, $k, None, None, Some($t));
    };
    ($s:ident, $n:ident, $l:literal, $k:expr) => {
        decode_test!($s, $n, $l, $k, None, None, None);
    };
    ($n:ident, $l:literal, $k:expr, $tt:ident, $t:expr) => {
        mod $n {
            use super::*;
            decode_test!(Rv32I, rv32i, $l, $k, $tt, $t);
            decode_test!(Rv64I, rv64i, $l, $k, $tt, $t);
        }
    };
    ($n:ident, $l:literal, None) => {
        mod $n {
            use super::*;
            decode_test!(Rv32I, rv32i, $l, None);
            decode_test!(Rv64I, rv64i, $l, None);
        }
    };
    ($n:ident, $l:literal, $k:expr) => {
        mod $n {
            use super::*;
            decode_test!(Rv32I, rv32i, $l, $k);
            decode_test!(Rv64I, rv64i, $l, $k);
        }
    };
}

decode_test!(mret, 0x30200073u32, Kind::mret);
decode_test!(sret, 0x10200073u32, Kind::sret);
decode_test!(fence, 0x0ff0000fu32, Kind::fence);
decode_test!(sfence_vma, 0x12010073u32, Kind::sfence_vma);
decode_test!(wfi, 0x10500073u32, Kind::wfi);
decode_test!(ecall, 0x00000073u32, Kind::ecall);
decode_test!(ebreak, 0x00100073u32, Kind::ebreak);
decode_test!(fence_i, 0x0000100fu32, Kind::fence_i);
decode_test!(beq, 0xaa360b63u32, Kind::new_beq(12, 3, -3402), b, -3402);
decode_test!(bne, 0xf4361963u32, Kind::new_bne(12, 3, -2222), b, -2222);
decode_test!(blt, 0x00004663u32, Kind::new_blt(0, 0, 12), b, 12);
decode_test!(bge, 0x845f5fe3u32, Kind::new_bge(30, 5, -1954), b, -1954);
decode_test!(bltu, 0x7f406fe3u32, Kind::new_bltu(0, 20, 4094), b, 4094);
decode_test!(bgeu, 0x01467063u32, Kind::new_bgeu(12, 20, 0), b, 0);
decode_test!(c_beqz, 0xca4du16, Kind::new_c_beqz(12, 178), b, 178);
decode_test!(c_beqz_u32, 0xca4du32, Kind::new_c_beqz(12, 178), b, 178);
decode_test!(c_benz, 0xe6cdu16, Kind::new_c_bnez(13, 170), b, 170);
decode_test!(auipc, 0xf2ab3697u32, Kind::new_auipc(13, -223662080));
decode_test!(lui, 0xfff0f8b7u32, Kind::new_lui(17, -987136));
decode_test!(c_lui, 0x7255u16, Kind::new_c_lui(4, -45056));
decode_test!(c_lui_rd0, 0x7055u16, None);
decode_test!(c_lui_rd2, 0x7155u16, None);
decode_test!(jal, 0x1030d66fu32, Kind::new_jal(12, 55554), j, 55554);
decode_test!(c_j, 0xab91u16, Kind::new_c_j(0, 1364), j, 1364);
decode_test!(c_jr, 0x8602u16, Kind::new_c_jr(12), u, (12, 0));
decode_test!(c_jalr, 0x9f82u16, Kind::new_c_jalr(31), u, (31, 0));
decode_test!(c_ebreak, 0x9002u16, Kind::c_ebreak);
decode_test!(
    jalr,
    0x66168867u32,
    Kind::new_jalr(16, 13, 0x661),
    u,
    (13, 0x661)
);
decode_test!(
    jalr_rs1_zero,
    0x66100fe7u32,
    Kind::new_jalr(31, 0, 1633),
    j,
    1633
);
decode_test!(jalr_fake, 0x6616f867u32, None);
decode_test!(nop, 0x00000013u32, Kind::nop);
decode_test!(c_nop, 0x0001u16, Kind::c_nop);

mod c_jal {
    use super::*;
    decode_test!(Rv32I, rv32i, 0x39f5u16, Kind::new_c_jal(0, -772), j, -772);
    decode_test!(Rv64I, rv64i, 0x39f5u16, None);
}

macro_rules! decode_test {
    ($name:ident, $bits:expr, $set:expr, None) => {
        #[test]
        fn $name() {
            let bits = $bits;
            let instruction = $set.decode_bits(bits);

            assert_eq!(instruction, None);
        }
    };
    ($name:ident, $bits:expr, $set:expr, $expected_kind:expr) => {
        #[test]
        fn $name() {
            let bits = $bits;
            let instruction = $set.decode_bits(bits);
            assert_eq!(instruction, Some($expected_kind));
        }
    };
}

// rd is 0 and immediate needs to be shifted by 1 to left to match logic f. TypeJ instructions
decode_test!(
    decode_16,
    Bits::Bit16(0b001_010_0010_0000_01),
    base::Set::Rv32I,
    Kind::new_c_jal(0, (0b_0000_0101_000) << 1)
);
decode_test!(
    decode_32,
    Bits::Bit32(0x35AA4163),
    base::Set::Rv32I,
    Kind::new_blt(20, 26, (0b0001_1010_0001) << 1)
);
decode_test!(decode_48, Bits::Bit48(0x63E3312B), base::Set::Rv64I, None);
decode_test!(decode_64, Bits::Bit64(0x218A202D), base::Set::Rv64I, None);

decode_test!(
    decode_16_none_c,
    Bits::Bit16(0b011_0_00000_10100_01),
    base::Set::Rv32I,
    None
);
decode_test!(
    decode_16_none_typej,
    Bits::Bit16(0b100_1_00000_00001_10),
    base::Set::Rv32I,
    None
);
decode_test!(
    decode_32_none_fence,
    Bits::Bit32(0b_110101110001_01001_011_01100_0001111),
    base::Set::Rv32I,
    None
);
decode_test!(
    decode_32_none_typeb,
    Bits::Bit32(0b0110110_00110_11101_010_00011_1100011),
    base::Set::Rv32I,
    None
);
decode_test!(
    decode_32_none_system,
    Bits::Bit32(0b000000100000_01010_000_01000_1110011),
    base::Set::Rv32I,
    None
);
decode_test!(
    decode_32_none,
    Bits::Bit32(0b0100011001101001010001000_11111111),
    base::Set::Rv32I,
    None
);
