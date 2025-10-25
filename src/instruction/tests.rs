// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::unusual_byte_groupings)]

extern crate alloc;

mod decode;
mod extract;
mod fmt;
mod insn_fmt;

use super::*;

use base::Set::{Rv32I, Rv64I};
use info::{Decode, Info};

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
