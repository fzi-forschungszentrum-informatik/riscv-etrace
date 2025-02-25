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

/// Simple [InstructionCache] of fixed size
#[derive(Clone, Debug)]
pub struct FixedSizedCache<const N: usize> {
    data: [(u64, Instruction); N],
    pos: usize,
    count: usize,
}

impl<const N: usize> Default for FixedSizedCache<N> {
    fn default() -> Self {
        Self {
            data: [Default::default(); N],
            pos: 0,
            count: 0,
        }
    }
}

impl<const N: usize> InstructionCache for FixedSizedCache<N> {
    fn store(&mut self, addr: u64, insn: Instruction) {
        self.data[self.pos] = (addr, insn);

        self.pos += 1;
        if self.pos > N {
            self.pos = 0;
        }

        self.count = self.count.saturating_add(1);
    }

    fn get(&self, addr: u64) -> Option<Instruction> {
        self.data
            .iter()
            .take(self.count)
            .cloned()
            .find(|(a, _)| *a == addr)
            .map(|(_, i)| i)
    }
}
