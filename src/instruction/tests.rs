// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::unusual_byte_groupings)]

extern crate alloc;

use super::*;

use base::Set::{Rv32I, Rv64I};
use info::{Decode, Info};

macro_rules! decode_test {
    ($s:ident, $n:ident, $l:literal, $k:expr, $bt:expr, $jt:expr, $uj:expr) => {
        #[test]
        fn $n() {
            let insn = DecodeForTest::decode($l, $s);
            assert_eq!(insn, $k);
            assert_eq!(insn.branch_target(), $bt);
            assert_eq!(insn.inferable_jump_target(), $jt);
            assert_eq!(insn.uninferable_jump_target(), $uj);
        }
    };
    ($s:ident, $n:ident, $l:literal, None) => {
        #[test]
        fn $n() {
            assert_eq!(DecodeForTest::try_decode($l, $s), None);
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

/// Helper trait for using the correct decoding fn depending on a literal's type
trait DecodeForTest: Sized {
    fn decode(self, base: base::Set) -> Kind {
        self.try_decode(base).expect("Could not decode")
    }

    fn try_decode(self, base: base::Set) -> Option<Kind>;
}

impl DecodeForTest for u16 {
    fn try_decode(self, base: base::Set) -> Option<Kind> {
        base.decode_16(self)
    }
}

impl DecodeForTest for u32 {
    fn try_decode(self, base: base::Set) -> Option<Kind> {
        base.decode_32(self)
    }
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

mod c_jal {
    use super::*;
    decode_test!(Rv32I, rv32i, 0x39f5u16, Kind::new_c_jal(0, -772), j, -772);
    decode_test!(Rv64I, rv64i, 0x39f5u16, None);
}

mod fmt {
    use alloc::string::ToString;

    use crate::instruction::format::{TypeR, TypeS};

    use super::*;

    pub mod kind_tests {
        use super::*;
        macro_rules! format_test {
            ($n:ident, $k:expr, $l:literal) => {
                #[test]
                fn $n() {
                    assert_eq!($k.to_string(), $l);
                }
            };
        }

        format_test!(c_jr, Kind::new_c_jr(12), "c.jr x12");
        format_test!(c_jalr, Kind::new_c_jalr(31), "c.jalr x31");
        format_test!(c_jal, Kind::new_c_jal(3, 0x5), "c.jal 0x5");
        format_test!(c_j, Kind::new_c_j(3, 0x15), "c.j 0x15");
        format_test!(jal, Kind::new_jal(5, 0x12), "jal x5, 0x12");
        // Right shift displayed immediate by 12 bit
        format_test!(c_lui, Kind::new_c_lui(3, 0x5000), "c.lui x3, 0x5");
        format_test!(auipc, Kind::new_auipc(5, 0x12000), "auipc x5, 0x12");
        format_test!(lui, Kind::new_lui(8, 0x135000), "lui x8, 0x135");
        format_test!(jalr, Kind::new_jalr(7, 5, 0x3057), "jalr x7, x5, 0x3057");
        format_test!(c_beqz, Kind::new_c_beqz(8, 0x333), "c.beqz x8, 0x333");
        format_test!(c_bnez, Kind::new_c_bnez(10, 0x812), "c.bnez x10, 0x812");
        format_test!(beq, Kind::new_beq(9, 11, 0x111), "beq x9, x11, 0x111");
        format_test!(bne, Kind::new_bne(12, 13, 0x555), "bne x12, x13, 0x555");
        format_test!(blt, Kind::new_blt(15, 12, 0x723), "blt x15, x12, 0x723");
        format_test!(bge, Kind::new_bge(10, 13, 0x444), "bge x10, x13, 0x444");
        format_test!(bltu, Kind::new_bltu(7, 11, 0x487), "bltu x7, x11, 0x487");
        format_test!(bgeu, Kind::new_bgeu(6, 14, 0x777), "bgeu x6, x14, 0x777");
        format_test!(c_ebreak, Kind::c_ebreak, "c.ebreak");
        format_test!(ebreak, Kind::ebreak, "ebreak");
        format_test!(fence_i, Kind::fence_i, "fence.i");
        format_test!(ecall, Kind::ecall, "ecall");
        format_test!(wfi, Kind::wfi, "wfi");
        format_test!(sfence_vma, Kind::sfence_vma, "sfence.vma");
        format_test!(fence, Kind::fence, "fence");
        format_test!(mret, Kind::mret, "mret");
        format_test!(sret, Kind::sret, "sret");
        format_test!(uret, Kind::uret, "uret");
        format_test!(dret, Kind::dret, "dret");
    }

    pub mod instruction_tests {
        use super::*;

        macro_rules! instruction_format_test {
            ($name:ident, $instruction:expr, $string_literal:expr) => {
                #[test]
                fn $name() {
                    assert_eq!($instruction.to_string(), $string_literal);
                }
            };
        }

        instruction_format_test!(
            instruction_with_kind,
            Instruction::from(Kind::new_beq(5, 12, 0x4F)),
            "beq x5, x12, 0x4F"
        );
        instruction_format_test!(
            instruction_without_kind,
            Instruction {
                size: Size::Normal,
                info: None
            },
            ""
        );
    }

    pub mod type_tests {
        use super::*;
        #[test]
        fn type_r_format_test() {
            let format_type = TypeR {
                rd: 5,
                rs1: 3,
                rs2: 12,
            }
            .to_string();
            assert_eq!(format_type, "x5, x3, x12");
        }

        #[test]
        fn type_s_format_test() {
            let format_type = TypeS {
                rs1: 7,
                rs2: 13,
                imm: 0x46F3,
            }
            .to_string();
            assert_eq!(format_type, "x7, x13, 0x46F3");
        }
    }
}

#[test]
fn type_r() {
    use format::TypeR;

    assert_eq!(
        TypeR::from(0x00000f80u32),
        TypeR {
            rd: 0x1f,
            rs1: 0x00,
            rs2: 0x00,
        },
    );
    assert_eq!(
        TypeR::from(0x000f8000u32),
        TypeR {
            rd: 0x00,
            rs1: 0x1f,
            rs2: 0x00,
        },
    );
    assert_eq!(
        TypeR::from(0x01f00000u32),
        TypeR {
            rd: 0x00,
            rs1: 0x00,
            rs2: 0x1f,
        },
    );

    assert_eq!(
        TypeR::from(0x0f80u16),
        TypeR {
            rd: 0x1f,
            rs1: 0x1f,
            rs2: 0x00,
        },
    );
    assert_eq!(
        TypeR::from(0x007cu16),
        TypeR {
            rd: 0x00,
            rs1: 0x00,
            rs2: 0x1f,
        },
    );
}

#[test]
fn type_i() {
    use format::TypeI;

    assert_eq!(
        TypeI::from(0x00000f80u32),
        TypeI {
            rd: 0x1f,
            rs1: 0x00,
            imm: 0x000,
        },
    );
    assert_eq!(
        TypeI::from(0x000f8000u32),
        TypeI {
            rd: 0x00,
            rs1: 0x1f,
            imm: 0x000,
        },
    );
    assert_eq!(
        TypeI::from(0xfff00000u32),
        TypeI {
            rd: 0x00,
            rs1: 0x00,
            imm: -1,
        },
    );
}

#[test]
fn type_s() {
    use format::TypeS;

    assert_eq!(
        TypeS::from(0x000f8000u32),
        TypeS {
            rs1: 0x1f,
            rs2: 0x00,
            imm: 0x000,
        },
    );
    assert_eq!(
        TypeS::from(0x01f00000u32),
        TypeS {
            rs1: 0x00,
            rs2: 0x1f,
            imm: 0x000,
        },
    );
    assert_eq!(
        TypeS::from(0x00000f80u32),
        TypeS {
            rs1: 0x00,
            rs2: 0x00,
            imm: 0x01f,
        },
    );
    assert_eq!(
        TypeS::from(0xfe000000u32),
        TypeS {
            rs1: 0x00,
            rs2: 0x00,
            imm: -0x020,
        },
    );
}

#[test]
fn type_b() {
    use format::TypeB;

    assert_eq!(
        TypeB::from(0x000f8000u32),
        TypeB {
            rs1: 0x1f,
            rs2: 0x00,
            imm: 0x0000,
        },
    );
    assert_eq!(
        TypeB::from(0x01f00000u32),
        TypeB {
            rs1: 0x00,
            rs2: 0x1f,
            imm: 0x0000,
        },
    );
    assert_eq!(
        TypeB::from(0x00000f00u32),
        TypeB {
            rs1: 0x00,
            rs2: 0x00,
            imm: 0x001e,
        },
    );
    assert_eq!(
        TypeB::from(0x7e000000u32),
        TypeB {
            rs1: 0x00,
            rs2: 0x00,
            imm: 0x07e0,
        },
    );
    assert_eq!(
        TypeB::from(0x00000080u32),
        TypeB {
            rs1: 0x00,
            rs2: 0x00,
            imm: 0x0800,
        },
    );
    assert_eq!(
        TypeB::from(0x80000000u32),
        TypeB {
            rs1: 0x00,
            rs2: 0x00,
            imm: -0x1000,
        },
    );

    assert_eq!(
        TypeB::from(0x0380u16),
        TypeB {
            rs1: 0x0f,
            rs2: 0x00,
            imm: 0x0000,
        },
    );
    assert_eq!(
        TypeB::from(0x0018u16),
        TypeB {
            rs1: 0x08,
            rs2: 0x00,
            imm: 0x0006,
        },
    );
    assert_eq!(
        TypeB::from(0x0c00u16),
        TypeB {
            rs1: 0x08,
            rs2: 0x00,
            imm: 0x0018,
        },
    );
    assert_eq!(
        TypeB::from(0x0004u16),
        TypeB {
            rs1: 0x08,
            rs2: 0x00,
            imm: 0x0020,
        },
    );
    assert_eq!(
        TypeB::from(0x0060u16),
        TypeB {
            rs1: 0x08,
            rs2: 0x00,
            imm: 0x00c0,
        },
    );
    assert_eq!(
        TypeB::from(0x1000u16),
        TypeB {
            rs1: 0x08,
            rs2: 0x00,
            imm: -0x100,
        },
    );
}

#[test]
fn type_u() {
    use format::TypeU;

    assert_eq!(
        TypeU::from(0x00000f80u32),
        TypeU {
            rd: 0x1f,
            imm: 0x00000000,
        },
    );
    assert_eq!(
        TypeU::from(0xfffff000u32),
        TypeU {
            rd: 0x00,
            imm: -0x00001000,
        },
    );

    assert_eq!(
        TypeU::from(0x0f80u16),
        TypeU {
            rd: 0x1f,
            imm: 0x0000000,
        },
    );
    assert_eq!(
        TypeU::from(0x007cu16),
        TypeU {
            rd: 0x00,
            imm: 0x001f000,
        },
    );
    assert_eq!(
        TypeU::from(0x1000u16),
        TypeU {
            rd: 0x00,
            imm: -0x0020000,
        },
    );
}

#[test]
fn type_j() {
    use format::TypeJ;

    assert_eq!(
        TypeJ::from(0x00000f80u32),
        TypeJ {
            rd: 0x1f,
            imm: 0x000000,
        },
    );
    assert_eq!(
        TypeJ::from(0x7fe00000u32),
        TypeJ {
            rd: 0x00,
            imm: 0x0007fe,
        },
    );
    assert_eq!(
        TypeJ::from(0x00100000u32),
        TypeJ {
            rd: 0x00,
            imm: 0x000800,
        },
    );
    assert_eq!(
        TypeJ::from(0x000ff000u32),
        TypeJ {
            rd: 0x00,
            imm: 0x0ff000,
        },
    );
    assert_eq!(
        TypeJ::from(0x80000000u32),
        TypeJ {
            rd: 0x00,
            imm: -0x100000,
        },
    );

    assert_eq!(
        TypeJ::from(0x0038u16),
        TypeJ {
            rd: 0x00,
            imm: 0x00e,
        },
    );
    assert_eq!(
        TypeJ::from(0x0800u16),
        TypeJ {
            rd: 0x00,
            imm: 0x010,
        },
    );
    assert_eq!(
        TypeJ::from(0x0004u16),
        TypeJ {
            rd: 0x00,
            imm: 0x020,
        },
    );
    assert_eq!(
        TypeJ::from(0x0080u16),
        TypeJ {
            rd: 0x00,
            imm: 0x040,
        },
    );
    assert_eq!(
        TypeJ::from(0x0040u16),
        TypeJ {
            rd: 0x00,
            imm: 0x080,
        },
    );
    assert_eq!(
        TypeJ::from(0x0600u16),
        TypeJ {
            rd: 0x00,
            imm: 0x300,
        },
    );
    assert_eq!(
        TypeJ::from(0x0100u16),
        TypeJ {
            rd: 0x00,
            imm: 0x400,
        },
    );
    assert_eq!(
        TypeJ::from(0x1000u16),
        TypeJ {
            rd: 0x00,
            imm: -0x800,
        },
    );
}

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
    let (instruction, remaining) = Instruction::extract(&bytes_reverse, &Rv32I)
        .expect("Cannot extract instruction from data stream!");

    // Ensure Instruction Size and Kind are correctly extracted
    let size = instruction.size;
    let info = instruction.info.expect("Instruction is unknown");
    assert_eq!(size, Size::Normal);
    assert_eq!(remaining, []);
    assert_eq!(info, Kind::new_auipc(16, 0b0001_0100_0100_0101_1100 << 12));
}

macro_rules! decode_test {
    ($name:ident, $bits:expr, $set:expr, None) => {
        #[test]
        fn $name() {
            use info::Decode;
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

macro_rules! upper_immediate_test {
    ($name:ident, $ctor:ident($rd:expr, $imm:expr), $expected:expr) => {
        #[test]
        fn $name() {
            let kind = Kind::$ctor($rd, $imm);
            let dummy_input = 0x500;
            let result = kind.upper_immediate(dummy_input);

            assert_eq!(result, $expected);
        }
    };
}

upper_immediate_test!(lui_ok, new_lui(5, 0x80010), Some((5, 0x80010)));

// PC + imm for auipc
upper_immediate_test!(auipc_ok, new_auipc(7, 0x55555), Some((7, (0x55A55))));
upper_immediate_test!(c_lui_ok, new_c_lui(3, 0x20), Some((3, 0x20)));
upper_immediate_test!(jal_ok, new_jal(3, 0x4359), None);

#[test]
fn is_call_test() {
    let jalr = Kind::new_jalr(1, 3, 2792);
    let lui = Kind::new_lui(4, 519603);
    assert!(jalr.is_call());
    assert!(!lui.is_call());
}

#[test]
fn is_return_test() {
    let jalr = Kind::new_jal(2, 2450);
    assert!(!jalr.is_return());
}

macro_rules! from_kind_test {
    ($name:ident, $kind:expr, $expected_size:expr) => {
        #[test]
        fn $name() {
            let instruction: Instruction = $kind.into();
            assert_eq!(instruction.size, $expected_size);
        }
    };
}
from_kind_test!(from_mret, Kind::mret, Size::Normal);
from_kind_test!(from_fence, Kind::fence, Size::Normal);
from_kind_test!(from_bltu, Kind::new_bltu(3, 5, 0b1001), Size::Normal);
from_kind_test!(from_c_lui, Kind::new_c_lui(8, 0b11000), Size::Compressed);
from_kind_test!(from_c_eabreak, Kind::c_ebreak, Size::Compressed);
from_kind_test!(from_ebreak, Kind::ebreak, Size::Normal);
from_kind_test!(
    from_auipc,
    Kind::new_auipc(12, 0b11110000101000101100),
    Size::Normal
);

#[allow(unused_macros)]
macro_rules! compare_test {
    ($n:ident, $b:expr) => {
        mod $n {
            use super::*;

            #[test]
            fn compare_16() {
                compare_infos_16($b)
            }

            compare_test!(compare_32_0, $b, 0, 29);
            compare_test!(compare_32_1, $b, 1, 29);
            compare_test!(compare_32_2, $b, 2, 29);
            compare_test!(compare_32_3, $b, 3, 29);
            compare_test!(compare_32_4, $b, 4, 29);
            compare_test!(compare_32_5, $b, 5, 29);
            compare_test!(compare_32_6, $b, 6, 29);
            compare_test!(compare_32_7, $b, 7, 29);
        }
    };
    ($n:ident, $b:expr, $i:expr, $o:expr) => {
        #[test]
        fn $n() {
            compare_infos_32($b, $i, $o)
        }
    };
}

#[cfg(feature = "riscv-isa")]
mod compare_riscv_isa {
    use super::*;

    compare_test!(
        rv32i,
        riscv_isa::Target {
            xlen: riscv_isa::Xlen::Rv32,
            privileged: true,
            supervisor_mode: true,
            c: true,
            zicsr: true,
            zifencei: true,
            ..Default::default()
        }
    );

    compare_test!(
        rv64i,
        riscv_isa::Target {
            xlen: riscv_isa::Xlen::Rv64,
            privileged: true,
            supervisor_mode: true,
            c: true,
            zicsr: true,
            zifencei: true,
            ..Default::default()
        }
    );
}

/// Compare [`Info`] outputs for a range of decoded insns against a reference
#[allow(dead_code)]
fn compare_infos_16<D, I>(base: D)
where
    D: Decode<I> + Clone,
    I: Info + core::fmt::Debug,
    I::Register: From<<Kind as Info>::Register> + core::fmt::Debug,
    base::Set: From<D>,
{
    let ours = base::Set::from(base.clone());
    (0..0x3fff)
        .flat_map(|h| {
            let high = h << 2;
            [0b00, 0b01, 0b10].map(|l| l | high)
        })
        .for_each(|i| compare_infos(ours.decode_16(i), base.decode_16(i), i))
}

/// Compare [`Info`] outputs for a range of decoded insns against a reference
#[allow(dead_code)]
fn compare_infos_32<D, I>(base: D, num: u32, ex: u8)
where
    D: Decode<I> + Clone,
    I: Info + core::fmt::Debug,
    I::Register: From<<Kind as Info>::Register> + core::fmt::Debug,
    base::Set: From<D>,
{
    let ours = base::Set::from(base.clone());
    let ex = ex - 2;
    ((num << ex)..((num + 1) << ex))
        .map(|i| i << 2 | 0b11)
        .filter(|i| i & 0b11100 != 0b11100)
        .for_each(|i| compare_infos(ours.decode_32(i), base.decode_32(i), i))
}

/// Compare the [`Info`] outputs of `Option<Kind>` to another [`Info`]
fn compare_infos<I>(kind: Option<Kind>, other: I, insn: impl core::fmt::LowerHex)
where
    I: Info + core::fmt::Debug,
    I::Register: From<<Kind as Info>::Register> + core::fmt::Debug,
{
    assert_eq!(
        kind.branch_target(),
        other.branch_target(),
        "Branch targets differ for {insn:0x} ({kind:?} vs. {other:?})"
    );
    assert_eq!(
        kind.inferable_jump_target(),
        other.inferable_jump_target(),
        "Inferable jump targets differ for {insn:0x} ({kind:?} vs. {other:?})"
    );
    assert_eq!(
        kind.uninferable_jump_target().map(|(r, i)| (r.into(), i)),
        other.uninferable_jump_target(),
        "Inferable jump targets differ for {insn:0x} ({kind:?} vs. {other:?})"
    );
    assert_eq!(
        kind.upper_immediate(0).map(|(r, i)| (r.into(), i)),
        other.upper_immediate(0),
        "Upper immediates at 0 differ for {insn:0x} ({kind:?} vs. {other:?})"
    );
    assert_eq!(
        kind.upper_immediate(0x8000).map(|(r, i)| (r.into(), i)),
        other.upper_immediate(0x8000),
        "Upper immediates at 0x8000 differ for {insn:0x} ({kind:?} vs. {other:?})"
    );
    assert_eq!(
        kind.is_return_from_trap(),
        other.is_return_from_trap(),
        "Disaggreement on return from trap for {insn:0x} ({kind:?} vs. {other:?})"
    );
    assert_eq!(
        kind.is_ecall_or_ebreak(),
        other.is_ecall_or_ebreak(),
        "Disaggreement on return from trap for {insn:0x} ({kind:?} vs. {other:?})"
    );
    assert_eq!(
        kind.is_call(),
        other.is_call(),
        "Disaggreement on return from trap for {insn:0x} ({kind:?} vs. {other:?})"
    );
    assert_eq!(
        kind.is_return(),
        other.is_return(),
        "Disaggreement on return from trap for {insn:0x} ({kind:?} vs. {other:?})"
    );
}
