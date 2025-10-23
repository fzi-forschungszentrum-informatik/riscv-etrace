// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

use super::*;

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
