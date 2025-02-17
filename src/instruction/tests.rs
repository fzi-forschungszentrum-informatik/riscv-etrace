// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

use super::*;

use InstructionBits::{Bit16, Bit32};

#[test]
fn mret() {
    let bin = Bit32(0x30200073);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Normal,
            name: Some(Name::mret),
            is_rs1_zero: false,
            is_branch: false,
            imm: None,
        }
    )
}

#[test]
fn sret() {
    let bin = Bit32(0x10200073);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Normal,
            name: Some(Name::sret),
            is_rs1_zero: false,
            is_branch: false,
            imm: None,
        }
    );
}

#[test]
fn fence() {
    let bin = Bit32(0x0ff0000f);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Normal,
            name: Some(Name::fence),
            is_rs1_zero: false,
            is_branch: false,
            imm: None,
        }
    )
}

#[test]
fn sfence_vma() {
    let bin = Bit32(0x12010073);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Normal,
            name: Some(Name::sfence_vma),
            is_rs1_zero: false,
            is_branch: false,
            imm: None,
        }
    )
}

#[test]
fn wfi() {
    let bin = Bit32(0x10500073);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Normal,
            name: Some(Name::wfi),
            is_rs1_zero: false,
            is_branch: false,
            imm: None,
        }
    )
}

#[test]
fn ecall() {
    let bin = Bit32(0x00000073);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Normal,
            name: Some(Name::ecall),
            is_rs1_zero: false,
            is_branch: false,
            imm: None,
        }
    )
}

#[test]
fn ebreak() {
    let bin = Bit32(0x00100073);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Normal,
            name: Some(Name::ebreak),
            is_rs1_zero: false,
            is_branch: false,
            imm: None,
        }
    )
}

#[test]
fn fence_i() {
    let bin = Bit32(0x0000100f);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Normal,

            name: Some(Name::fence_i),
            is_rs1_zero: false,
            is_branch: false,
            imm: None,
        }
    )
}

#[test]
fn beq() {
    let bin = Bit32(0xaa360b63);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Normal,
            name: Some(Name::beq),
            is_branch: true,
            imm: Some(-3402),
            is_rs1_zero: false,
        }
    )
}

#[test]
fn bne() {
    let bin = Bit32(0xf4361963);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Normal,
            name: Some(Name::bne),
            is_branch: true,
            imm: Some(-2222),
            is_rs1_zero: false,
        }
    )
}

#[test]
fn blt() {
    let bin = Bit32(0x00004663);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Normal,
            name: Some(Name::blt),
            is_branch: true,
            imm: Some(12),
            is_rs1_zero: false,
        }
    )
}

#[test]
fn bge() {
    let bin = Bit32(0x845f5fe3);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Normal,
            name: Some(Name::bge),
            is_branch: true,
            imm: Some(-1954),
            is_rs1_zero: false,
        }
    )
}

#[test]
fn bltu() {
    let bin = Bit32(0x7f406fe3);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Normal,
            name: Some(Name::bltu),
            is_branch: true,
            imm: Some(4094),
            is_rs1_zero: false,
        }
    )
}

#[test]
fn bgeu() {
    let bin = Bit32(0x01467063);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Normal,
            name: Some(Name::bgeu),
            is_branch: true,
            imm: Some(0),
            is_rs1_zero: false,
        }
    )
}

#[test]
fn c_beqz() {
    let bin = Bit16(0xca4d);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Compressed,
            name: Some(Name::c_beqz),
            is_branch: true,
            imm: Some(178),
            is_rs1_zero: false,
        }
    )
}

#[test]
fn c_benz() {
    let bin = Bit16(0xe6cd);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Compressed,
            name: Some(c_bnez),
            is_branch: true,
            imm: Some(170),
            is_rs1_zero: false
        }
    )
}

#[test]
fn auipc() {
    let bin = Bit32(0xf2ab3697);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Normal,
            name: Some(Name::auipc),
            is_branch: false,
            imm: Some(-54605),
            is_rs1_zero: false,
        }
    )
}

#[test]
fn lui() {
    let bin = Bit32(0xfff0f8b7);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Normal,
            name: Some(Name::lui),
            is_branch: false,
            imm: Some(-241),
            is_rs1_zero: false,
        }
    )
}

#[test]
fn c_lui() {
    let bin = Bit16(0x7255);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Compressed,
            name: Some(Name::c_lui),
            is_branch: false,
            imm: Some(-11),
            is_rs1_zero: false,
        }
    )
}

#[test]
fn jal() {
    let bin = Bit32(0x1030d66f);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Normal,
            name: Some(Name::jal),
            is_branch: false,
            imm: Some(55554),
            is_rs1_zero: false,
        }
    )
}

#[test]
fn c_j() {
    let bin = Bit16(0xab91);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Compressed,
            name: Some(Name::c_j),
            is_branch: false,
            imm: Some(1364),
            is_rs1_zero: false,
        }
    )
}

#[test]
fn c_jal() {
    let bin = Bit16(0x39f5);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Compressed,
            name: Some(Name::c_jal),
            is_branch: false,
            imm: Some(-772),
            is_rs1_zero: false,
        }
    )
}

#[test]
fn c_jr() {
    let bin = Bit16(0x8602);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Compressed,
            name: Some(Name::c_jr),
            is_branch: false,
            imm: None,
            is_rs1_zero: false,
        }
    )
}

#[test]
fn c_jalr() {
    let bin = Bit16(0x9f82);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Compressed,
            name: Some(Name::c_jalr),
            is_branch: false,
            imm: None,
            is_rs1_zero: false,
        }
    )
}

#[test]
fn c_ebreak() {
    let bin = Bit16(0x9002);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Compressed,
            name: Some(Name::c_ebreak),
            is_branch: false,
            imm: None,
            is_rs1_zero: false,
        }
    )
}

#[test]
fn jalr() {
    let bin = Bit32(0x66168867);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Normal,
            name: Some(Name::jalr),
            imm: None,
            is_rs1_zero: false,
            is_branch: false,
        }
    )
}

#[test]
fn jalr_rs1_zero() {
    let bin = Bit32(0x66100fe7);
    assert_eq!(
        Instruction::from_binary(&bin),
        Instruction {
            size: InstructionSize::Normal,
            name: Some(Name::jalr),
            imm: Some(1633),
            is_rs1_zero: true,
            is_branch: false,
        }
    )
}
