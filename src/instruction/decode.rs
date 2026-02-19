// Copyright (C) 2026 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Instruction decode

use crate::config::Parameters;

use super::bits::Bits;
use super::info::Info;

/// Decode for instruction [`Info`]
pub trait Decode<I: Info> {
    /// Decode a 16bit ("compressed") instruction [`Info`]
    fn decode_16(&self, insn: u16) -> I;

    /// Decode a 32bit ("normal") instruction [`Info`]
    fn decode_32(&self, insn: u32) -> I;

    /// Decode a 48bit instruction [`Info`]
    fn decode_48(&self, insn: u64) -> I;

    /// Decode a 64bit instruction [`Info`]
    fn decode_64(&self, insn: u64) -> I;

    /// Decode instruction [`Info`] from [`Bits`]
    fn decode_bits(&self, bits: Bits) -> I {
        match bits {
            Bits::Bit16(bits) => self.decode_16(bits),
            Bits::Bit32(bits) => self.decode_32(bits),
            Bits::Bit48(bits) => self.decode_48(bits),
            Bits::Bit64(bits) => self.decode_64(bits),
        }
    }
}

#[cfg(feature = "riscv-isa")]
impl Decode<riscv_isa::Instruction> for riscv_isa::Target {
    fn decode_16(&self, insn: u16) -> riscv_isa::Instruction {
        use riscv_isa::Compressed;

        // Version 0.3.1 of `riscv-isa` wrongly decodes some instructions as
        // `c.lui`, `c.jr` or `c.jalr`.
        match riscv_isa::decode_compressed(insn, self) {
            Compressed::C_LUI { rd: 0, .. } => Compressed::UNIMP,
            Compressed::C_JR { rs1: 0, .. } => Compressed::UNIMP,
            Compressed::C_JALR { rs1: 0, .. } => Compressed::UNIMP,
            insn => insn,
        }
        .into()
    }

    fn decode_32(&self, insn: u32) -> riscv_isa::Instruction {
        riscv_isa::decode_full(insn, self)
    }

    fn decode_48(&self, _insn: u64) -> riscv_isa::Instruction {
        riscv_isa::Instruction::UNIMP
    }

    fn decode_64(&self, _insn: u64) -> riscv_isa::Instruction {
        riscv_isa::Instruction::UNIMP
    }
}

#[cfg(feature = "riscv-isa")]
impl Decode<riscv_isa::Compressed> for riscv_isa::Target {
    fn decode_16(&self, insn: u16) -> riscv_isa::Compressed {
        use riscv_isa::Compressed;

        // Version 0.3.1 of `riscv-isa` wrongly decodes some instructions as
        // `c.lui`, `c.jr` or `c.jalr`.
        match riscv_isa::decode_compressed(insn, self) {
            Compressed::C_LUI { rd: 0, .. } => Compressed::UNIMP,
            Compressed::C_JR { rs1: 0, .. } => Compressed::UNIMP,
            Compressed::C_JALR { rs1: 0, .. } => Compressed::UNIMP,
            insn => insn,
        }
    }

    fn decode_32(&self, _insn: u32) -> riscv_isa::Compressed {
        riscv_isa::Compressed::UNIMP
    }

    fn decode_48(&self, _insn: u64) -> riscv_isa::Compressed {
        riscv_isa::Compressed::UNIMP
    }

    fn decode_64(&self, _insn: u64) -> riscv_isa::Compressed {
        riscv_isa::Compressed::UNIMP
    }
}

#[cfg(all(feature = "either", feature = "riscv-isa"))]
impl Decode<either::Either<riscv_isa::Compressed, riscv_isa::Instruction>> for riscv_isa::Target {
    fn decode_16(
        &self,
        insn: u16,
    ) -> either::Either<riscv_isa::Compressed, riscv_isa::Instruction> {
        either::Left(self.decode_16(insn))
    }

    fn decode_32(
        &self,
        insn: u32,
    ) -> either::Either<riscv_isa::Compressed, riscv_isa::Instruction> {
        either::Right(self.decode_32(insn))
    }

    fn decode_48(
        &self,
        insn: u64,
    ) -> either::Either<riscv_isa::Compressed, riscv_isa::Instruction> {
        either::Right(self.decode_48(insn))
    }

    fn decode_64(
        &self,
        insn: u64,
    ) -> either::Either<riscv_isa::Compressed, riscv_isa::Instruction> {
        either::Right(self.decode_64(insn))
    }
}

/// Make a [`Decode`]
///
/// This trait allows type agnostic creation of some [`Decode`] values, provided
/// that the type it is implemented for functions as one.
pub trait MakeDecode {
    /// Create a [`Decode`] for RV32I with all extensions enabled
    ///
    /// The resulting [`Decode`] decodes any instruction based on RV32I known to
    /// it. It is not configured according to limitations of a specific target
    /// CPU.
    fn rv32i_full() -> Self;

    /// Create a [`Decode`] for RV64I with all extensions enabled
    ///
    /// The resulting [`Decode`] decodes any instruction based on RV64I known to
    /// it. It is not configured according to limitations of a specific target
    /// CPU.
    fn rv64i_full() -> Self;

    /// Infer a [`Decode`] value from the given [`Parameters`]
    ///
    /// The value is (currently) inferred from the `iaddress_width_p` parameter.
    /// The base set with the lowest general purpose register greater than
    /// `iaddress_width_p` will be selected.
    fn infer_from_params(params: &Parameters) -> Option<Self>
    where
        Self: Sized,
    {
        match params.iaddress_width_p.get() {
            0..=32 => Some(Self::rv32i_full()),
            33..=64 => Some(Self::rv64i_full()),
            _ => None,
        }
    }
}

#[cfg(feature = "riscv-isa")]
impl MakeDecode for riscv_isa::Target {
    fn rv32i_full() -> Self {
        Self {
            xlen: riscv_isa::Xlen::Rv32,
            privileged: true,
            supervisor_mode: true,
            m: true,
            a: true,
            f: true,
            d: true,
            q: true,
            c: true,
            zicsr: true,
            zifencei: true,
            zawrs: true,
            zfh: true,
            zba: true,
            zbb: true,
            zbc: true,
            zbkb: true,
            zbs: true,
        }
    }

    fn rv64i_full() -> Self {
        Self {
            xlen: riscv_isa::Xlen::Rv64,
            privileged: true,
            supervisor_mode: true,
            m: true,
            a: true,
            f: true,
            d: true,
            q: true,
            c: true,
            zicsr: true,
            zifencei: true,
            zawrs: true,
            zfh: true,
            zba: true,
            zbb: true,
            zbc: true,
            zbkb: true,
            zbs: true,
        }
    }
}
