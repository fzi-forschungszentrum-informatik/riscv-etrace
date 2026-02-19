// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

extern crate alloc;

mod compare;
mod decode_tests;
mod extract;
mod fmt;
mod insn_fmt;

use super::*;

use base::Set::{Rv32I, Rv64I};
use decode::Decode;
use info::Info;

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
