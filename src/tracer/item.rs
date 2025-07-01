// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Tracing item

use crate::instruction::{self, Instruction};
use crate::types::trap;

/// Tracing item
///
/// A tracing item corresponds to a traced instruction. It contains that
/// [`Instruction`], its address and other information.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pc: u64,
    insn: Instruction,
    trap: Option<(u64, trap::Info)>,
}

impl Item {
    /// Create a new item for the given [`Instruction`] at the given PC
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

    /// Retrieve the [`Instruction`]
    pub fn instruction(&self) -> Instruction {
        self.insn
    }

    /// Retrieve the EPC and [`trap::Info`] of this item if present
    ///
    /// Any trap information is present only for the first item after the trap.
    pub fn trap(&self) -> Option<&(u64, trap::Info)> {
        self.trap.as_ref()
    }
}

/// Kind of a tracing [`Item`]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Signals the retiring of the [`Instruction`] at the [`Item`]'s PC
    Regular(Instruction),
    /// Signals a trap
    ///
    /// In the case of an exception, the [`Item`]'s PC indicated the EPC. In the
    /// case of an interrupt, the PC will point at the last [`Instruction`]
    /// retired before the interrut.
    Trap(trap::Info),
}

impl From<Instruction> for Kind {
    fn from(insn: Instruction) -> Self {
        Self::Regular(insn)
    }
}

impl From<instruction::Kind> for Kind {
    fn from(insn: instruction::Kind) -> Self {
        Self::Regular(insn.into())
    }
}

impl From<trap::Info> for Kind {
    fn from(info: trap::Info) -> Self {
        Self::Trap(info)
    }
}
