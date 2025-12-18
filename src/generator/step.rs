// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Tracing encoder inputs associated to single execution steps

use crate::instruction::{self, Instruction};
use crate::types::{trap, Context};

use super::hart2enc::{CType, IType, JumpType};

use instruction::info::Info;

/// Tracing data emitted by a HART in a single execution step
pub trait Step {
    /// Address relevant for this step
    ///
    /// For instruction retirement, this value if the address of the retired
    /// instruction.
    fn address(&self) -> u64;

    /// Step kind
    fn kind(&self) -> Kind;

    /// Context type
    fn ctype(&self) -> CType;

    /// Execution [`Context`]
    fn context(&self) -> Context;

    /// Timestamp
    fn timestamp(&self) -> Option<u64> {
        None
    }

    /// Refine this step's data with information from the next step
    fn refine(&mut self, _next: &Self) {}
}

/// Step kind
///
/// Instances of this type express different kinds of steps and encapsulate
/// data relevant only for specific kinds.
#[derive(Copy, Clone, Debug)]
pub enum Kind {
    /// Regular instruction retirement
    Retirement {
        /// Size of the retired instruction
        insn_size: instruction::Size,
    },
    /// Trap
    Trap {
        /// Size of the retired instruction, if any
        ///
        /// Exceptions and interrupts happen without simultaneaous retirement,
        /// with the exception of `ecall` and similar instructions. For those,
        /// this value holds the size of that instruction.
        insn_size: Option<instruction::Size>,
        /// Trap info
        info: trap::Info,
    },
    /// Trap return via an `xret` instruction
    TrapReturn {
        /// Size of the retired instruction
        insn_size: instruction::Size,
    },
    /// Retirement of a branch instruction
    Branch {
        /// Size of the retired branch instruction
        insn_size: instruction::Size,
        /// Indicator of whether the branch was taken or not
        taken: bool,
    },
    /// Retirement of a jump instruction
    Jump {
        /// Size of the retired jump instruction
        insn_size: instruction::Size,
        /// Type of the jump
        kind: JumpType,
        /// Indicator of whether the jump is sequentially inferable
        ///
        /// This indicator only has any meaning for uninferable jumps.
        sequentially_inferable: bool,
    },
}

impl Kind {
    /// Determine whether this is a trap without simultaneous retirement
    ///
    /// Returns `true` if this step kind refers to an "exception" (trap) without
    /// simultaneous retirement, `false` otherwise.
    pub fn is_exc_only(self) -> bool {
        matches!(
            self,
            Kind::Trap {
                insn_size: None,
                ..
            }
        )
    }

    /// Determint whether this is an uninferable PC dicontinuity
    ///
    /// Returns `true` if this step kind refers to an uninferable PC
    /// discontinuity, i.e. a jump. Sequentially inferable jumps are considered
    /// uninferable unless `true` if passed for `infer_sequentially`.
    pub fn is_updiscon(self, infer_sequentially: bool) -> bool {
        if let Self::Jump {
            kind,
            sequentially_inferable,
            ..
        } = self
        {
            !(kind.is_inferable() || (infer_sequentially && sequentially_inferable))
        } else {
            false
        }
    }

    /// Retrieve the [`instruction::Size`] of this step's final retirement
    ///
    /// Returns the size of the final instruction retired in this step, if any.
    /// [`Self::Trap`] is the only step kind that may not have a retirement.
    pub fn instruction_size(self) -> Option<instruction::Size> {
        match self {
            Self::Retirement { insn_size } => Some(insn_size),
            Self::Trap { insn_size, .. } => insn_size,
            Self::TrapReturn { insn_size } => Some(insn_size),
            Self::Branch { insn_size, .. } => Some(insn_size),
            Self::Jump { insn_size, .. } => Some(insn_size),
        }
    }

    /// Create a step kind from a retired [`Instruction`]
    pub fn from_instruction<I: Info>(
        insn: Instruction<I>,
        branch_taken: bool,
        prev_immediate: Option<I::Register>,
    ) -> Self {
        let insn_size = insn.size;
        if insn.is_return_from_trap() {
            return Self::TrapReturn { insn_size };
        };

        if insn.is_branch() {
            return Self::Branch {
                insn_size,
                taken: branch_taken,
            };
        }

        if let Some((target, _)) = insn.uninferable_jump_target() {
            let kind = if insn.is_call() {
                JumpType::UnferCall
            } else if insn.is_return() {
                JumpType::Return
            } else {
                JumpType::UnferOther
            };

            return Self::Jump {
                insn_size,
                kind,
                sequentially_inferable: Some(target) == prev_immediate,
            };
        } else if insn.is_inferable_jump() {
            let kind = if insn.is_call() {
                JumpType::InferCall
            } else {
                JumpType::InferOther
            };

            return Self::Jump {
                insn_size,
                kind,
                sequentially_inferable: false,
            };
        }

        Self::Retirement { insn_size }
    }

    /// Create a step kind from values usually exposed via signals by a HART
    pub fn from_hart(
        itype: IType,
        ecause: u16,
        tval: u64,
        insn_size: instruction::Size,
        retired: bool,
        sequentially_inferable: bool,
    ) -> Self {
        match itype {
            IType::Other => Self::Retirement { insn_size },
            IType::Exception => Self::Trap {
                insn_size: retired.then_some(insn_size),
                info: trap::Info {
                    ecause,
                    tval: Some(tval),
                },
            },
            IType::Interrupt => Self::Trap {
                insn_size: retired.then_some(insn_size),
                info: trap::Info { ecause, tval: None },
            },
            IType::ExReturn => Self::TrapReturn { insn_size },
            IType::Branch { taken } => Self::Branch { insn_size, taken },
            IType::Jump(kind) => Self::Jump {
                insn_size,
                kind,
                sequentially_inferable,
            },
        }
    }
}
