// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Tracing item

use crate::instruction::Instruction;
use crate::types::trap;

/// Tracing item
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pc: u64,
    insn: Instruction,
    trap: Option<(u64, trap::Info)>,
}

impl Item {
    /// Create a new item for the given [Instruction] at the given PC
    pub fn new(pc: u64, insn: Instruction) -> Self {
        Self {
            pc,
            insn,
            trap: None,
        }
    }

    /// Add trap information to this item
    pub fn with_trap(self, epc: u64, info: trap::Info) -> Self {
        Self {
            trap: Some((epc, info)),
            ..self
        }
    }

    /// Retrieve the PC
    pub fn pc(&self) -> u64 {
        self.pc
    }

    /// Retrieve the [Instruction]
    pub fn instruction(&self) -> Instruction {
        self.insn
    }

    /// Retrieve the EPC and [trap::Info] of this item if present
    ///
    /// Any trap information is present only for the first item after the trap.
    pub fn trap(&self) -> Option<&(u64, trap::Info)> {
        self.trap.as_ref()
    }
}
