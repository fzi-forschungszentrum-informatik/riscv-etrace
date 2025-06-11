// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

use super::*;

use base::Set::Rv32I;

macro_rules! decode_test {
    ($s:ident, $n:ident, $l:literal, $k:expr, $bt:expr, $jt:expr, $uj:expr) => {
        #[test]
        fn $n() {
            let insn = DecodeForTest::decode($l, $s);
            assert_eq!(insn, $k);
            assert_eq!(insn.branch_target(), $bt);
            assert_eq!(insn.inferable_jump_target(), $jt);
            assert_eq!(insn.uninferable_jump(), $uj);
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
        }
    };
    ($n:ident, $l:literal, $k:expr) => {
        mod $n {
            use super::*;
            decode_test!(Rv32I, rv32i, $l, $k);
        }
    };
}

/// Helper trait for using the correct decoding fn depending on a literal's type
trait DecodeForTest {
    fn decode(self, base: base::Set) -> Kind;
}

impl DecodeForTest for u16 {
    fn decode(self, base: base::Set) -> Kind {
        base.decode_16(self).expect("Could not decode")
    }
}

impl DecodeForTest for u32 {
    fn decode(self, base: base::Set) -> Kind {
        base.decode_32(self).expect("Could not decode")
    }
}

#[test]
fn mret() {
    let insn = Rv32I.decode_32(0x30200073).expect("Could not decode");
    assert_eq!(insn, Kind::mret);
    assert_eq!(insn.branch_target(), None);
    assert_eq!(insn.inferable_jump_target(), None);
    assert_eq!(insn.uninferable_jump(), None);
}

#[test]
fn sret() {
    let insn = Rv32I.decode_32(0x10200073).expect("Could not decode");
    assert_eq!(insn, Kind::sret);
    assert_eq!(insn.branch_target(), None);
    assert_eq!(insn.inferable_jump_target(), None);
    assert_eq!(insn.uninferable_jump(), None);
}

#[test]
fn fence() {
    let insn = Rv32I.decode_32(0x0ff0000f).expect("Could not decode");
    assert_eq!(insn, Kind::fence);
    assert_eq!(insn.branch_target(), None);
    assert_eq!(insn.inferable_jump_target(), None);
    assert_eq!(insn.uninferable_jump(), None);
}

#[test]
fn sfence_vma() {
    let insn = Rv32I.decode_32(0x12010073).expect("Could not decode");
    assert_eq!(insn, Kind::sfence_vma);
    assert_eq!(insn.branch_target(), None);
    assert_eq!(insn.inferable_jump_target(), None);
    assert_eq!(insn.uninferable_jump(), None);
}

#[test]
fn wfi() {
    let insn = Rv32I.decode_32(0x10500073).expect("Could not decode");
    assert_eq!(insn, Kind::wfi);
    assert_eq!(insn.branch_target(), None);
    assert_eq!(insn.inferable_jump_target(), None);
    assert_eq!(insn.uninferable_jump(), None);
}

#[test]
fn ecall() {
    let insn = Rv32I.decode_32(0x00000073).expect("Could not decode");
    assert_eq!(insn, Kind::ecall);
    assert_eq!(insn.branch_target(), None);
    assert_eq!(insn.inferable_jump_target(), None);
    assert_eq!(insn.uninferable_jump(), None);
}

#[test]
fn ebreak() {
    let insn = Rv32I.decode_32(0x00100073).expect("Could not decode");
    assert_eq!(insn, Kind::ebreak);
    assert_eq!(insn.branch_target(), None);
    assert_eq!(insn.inferable_jump_target(), None);
    assert_eq!(insn.uninferable_jump(), None);
}

#[test]
fn fence_i() {
    let insn = Rv32I.decode_32(0x0000100f).expect("Could not decode");
    assert_eq!(insn, Kind::fence_i);
    assert_eq!(insn.branch_target(), None);
    assert_eq!(insn.inferable_jump_target(), None);
    assert_eq!(insn.uninferable_jump(), None);
}

#[test]
fn beq() {
    let insn = Rv32I.decode_32(0xaa360b63).expect("Could not decode");
    assert_eq!(insn, Kind::new_beq(12, 3, -3402));
    assert_eq!(insn.branch_target(), Some(-3402));
    assert_eq!(insn.inferable_jump_target(), None);
    assert_eq!(insn.uninferable_jump(), None);
}

#[test]
fn bne() {
    let insn = Rv32I.decode_32(0xf4361963).expect("Could not decode");
    assert_eq!(insn, Kind::new_bne(12, 3, -2222));
    assert_eq!(insn.branch_target(), Some(-2222));
    assert_eq!(insn.inferable_jump_target(), None);
    assert_eq!(insn.uninferable_jump(), None);
}

#[test]
fn blt() {
    let insn = Rv32I.decode_32(0x00004663).expect("Could not decode");
    assert_eq!(insn, Kind::new_blt(0, 0, 12));
    assert_eq!(insn.branch_target(), Some(12));
    assert_eq!(insn.inferable_jump_target(), None);
    assert_eq!(insn.uninferable_jump(), None);
}

#[test]
fn bge() {
    let insn = Rv32I.decode_32(0x845f5fe3).expect("Could not decode");
    assert_eq!(insn, Kind::new_bge(30, 5, -1954));
    assert_eq!(insn.branch_target(), Some(-1954));
    assert_eq!(insn.inferable_jump_target(), None);
    assert_eq!(insn.uninferable_jump(), None);
}

#[test]
fn bltu() {
    let insn = Rv32I.decode_32(0x7f406fe3).expect("Could not decode");
    assert_eq!(insn, Kind::new_bltu(0, 20, 4094));
    assert_eq!(insn.branch_target(), Some(4094));
    assert_eq!(insn.inferable_jump_target(), None);
    assert_eq!(insn.uninferable_jump(), None);
}

#[test]
fn bgeu() {
    let insn = Rv32I.decode_32(0x01467063).expect("Could not decode");
    assert_eq!(insn, Kind::new_bgeu(12, 20, 0));
    assert_eq!(insn.branch_target(), Some(0));
    assert_eq!(insn.inferable_jump_target(), None);
    assert_eq!(insn.uninferable_jump(), None);
}

#[test]
fn c_beqz() {
    let insn = Rv32I.decode_16(0xca4d).expect("Could not decode");
    assert_eq!(insn, Kind::new_c_beqz(12, 178));
    assert_eq!(insn.branch_target(), Some(178));
    assert_eq!(insn.inferable_jump_target(), None);
    assert_eq!(insn.uninferable_jump(), None);
}

#[test]
fn c_benz() {
    let insn = Rv32I.decode_16(0xe6cd).expect("Could not decode");
    assert_eq!(insn, Kind::new_c_bnez(13, 170));
    assert_eq!(insn.branch_target(), Some(170));
    assert_eq!(insn.inferable_jump_target(), None);
    assert_eq!(insn.uninferable_jump(), None);
}

#[test]
fn auipc() {
    let insn = Rv32I.decode_32(0xf2ab3697).expect("Could not decode");
    assert_eq!(insn, Kind::new_auipc(13, -223662080));
    assert_eq!(insn.branch_target(), None);
    assert_eq!(insn.inferable_jump_target(), None);
    assert_eq!(insn.uninferable_jump(), None);
}

#[test]
fn lui() {
    let insn = Rv32I.decode_32(0xfff0f8b7).expect("Could not decode");
    assert_eq!(insn, Kind::new_lui(17, -987136));
    assert_eq!(insn.branch_target(), None);
    assert_eq!(insn.inferable_jump_target(), None);
    assert_eq!(insn.uninferable_jump(), None);
}

#[test]
fn c_lui() {
    let insn = Rv32I.decode_16(0x7255).expect("Could not decode");
    assert_eq!(insn, Kind::new_c_lui(4, -45056));
    assert_eq!(insn.branch_target(), None);
    assert_eq!(insn.inferable_jump_target(), None);
    assert_eq!(insn.uninferable_jump(), None);
}

#[test]
fn jal() {
    let insn = Rv32I.decode_32(0x1030d66f).expect("Could not decode");
    assert_eq!(insn, Kind::new_jal(12, 55554));
    assert_eq!(insn.branch_target(), None);
    assert_eq!(insn.inferable_jump_target(), Some(55554));
    assert_eq!(insn.uninferable_jump(), None);
}

#[test]
fn c_j() {
    let insn = Rv32I.decode_16(0xab91).expect("Could not decode");
    assert_eq!(insn, Kind::new_c_j(0, 1364));
    assert_eq!(insn.branch_target(), None);
    assert_eq!(insn.inferable_jump_target(), Some(1364));
    assert_eq!(insn.uninferable_jump(), None);
}

#[test]
fn c_jal() {
    let insn = Rv32I.decode_16(0x39f5).expect("Could not decode");
    assert_eq!(insn, Kind::new_c_jal(0, -772));
    assert_eq!(insn.branch_target(), None);
    assert_eq!(insn.inferable_jump_target(), Some(-772));
    assert_eq!(insn.uninferable_jump(), None);
}

#[test]
fn c_jr() {
    let insn = Rv32I.decode_16(0x8602).expect("Could not decode");
    assert_eq!(insn, Kind::new_c_jr(12));
    assert_eq!(insn.branch_target(), None);
    assert_eq!(insn.inferable_jump_target(), None);
    assert_eq!(insn.uninferable_jump(), Some((12, 0)));
}

#[test]
fn c_jalr() {
    let insn = Rv32I.decode_16(0x9f82).expect("Could not decode");
    assert_eq!(insn, Kind::new_c_jalr(31));
    assert_eq!(insn.branch_target(), None);
    assert_eq!(insn.inferable_jump_target(), None);
    assert_eq!(insn.uninferable_jump(), Some((31, 0)));
}

#[test]
fn c_ebreak() {
    let insn = Rv32I.decode_16(0x9002).expect("Could not decode");
    assert_eq!(insn, Kind::c_ebreak);
    assert_eq!(insn.branch_target(), None);
    assert_eq!(insn.inferable_jump_target(), None);
    assert_eq!(insn.uninferable_jump(), None);
}

#[test]
fn jalr() {
    let insn = Rv32I.decode_32(0x66168867).expect("Could not decode");
    assert_eq!(insn, Kind::new_jalr(16, 13, 0x661));
    assert_eq!(insn.branch_target(), None);
    assert_eq!(insn.inferable_jump_target(), None);
    assert_eq!(insn.uninferable_jump(), Some((13, 0x661)));
}

#[test]
fn jalr_rs1_zero() {
    let insn = Rv32I.decode_32(0x66100fe7).expect("Could not decode");
    assert_eq!(insn, Kind::new_jalr(31, 0, 1633));
    assert_eq!(insn.branch_target(), None);
    assert_eq!(insn.inferable_jump_target(), Some(1633));
    assert_eq!(insn.uninferable_jump(), None);
}

// Instruction type related tests

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
        TypeU::from(0x003cu16),
        TypeU {
            rd: 0x00,
            imm: 0x000f000,
        },
    );
    assert_eq!(
        TypeU::from(0x1000u16),
        TypeU {
            rd: 0x00,
            imm: -0x0010000,
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

#[test]
fn bits_extract_16() {
    let data = [0x14, 0x41, 0x11, 0x05];
    assert_eq!(
        Bits::extract(&data),
        Some((Bits::Bit16(0x4114), [0x11, 0x05].as_slice())),
    );
}

#[test]
fn bits_extract_32() {
    let data = [0x97, 0x06, 0x00, 0x00, 0x93, 0x86, 0x86, 0x05];
    assert_eq!(
        Bits::extract(&data),
        Some((Bits::Bit32(0x00000697), [0x93, 0x86, 0x86, 0x05].as_slice())),
    );
}
