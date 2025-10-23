// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::unusual_byte_groupings)]

extern crate alloc;

mod decode;
mod fmt;

use super::*;

use base::Set::{Rv32I, Rv64I};
use info::{Decode, Info};

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
