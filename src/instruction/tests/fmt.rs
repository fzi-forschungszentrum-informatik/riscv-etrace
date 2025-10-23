// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Tests covering Display impls

use super::*;

use alloc::string::ToString;

use crate::instruction::format::{TypeR, TypeS};

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
