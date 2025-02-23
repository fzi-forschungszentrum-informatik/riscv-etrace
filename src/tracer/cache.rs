// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

use super::disassembler::Instruction;

/// A cache for [Instruction]s
pub trait InstructionCache {
    /// Store an [Instruction] in the cache
    ///
    /// If the cache is full, this operation evicts the least recently stored
    /// [Instruction].
    fn store(&mut self, addr: u64, insn: Instruction);

    /// Retrieve an [Instruction] by address
    fn get(&self, addr: u64) -> Option<Instruction>;
}
