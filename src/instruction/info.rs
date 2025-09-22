// Copyright (C) 2024, 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Instruction information

/// Instruction information
///
/// This trait defines fns for querying control flow relevant information of
/// individual instructions.
pub trait Info {
    /// Type for representing a register address
    type Register: Clone + PartialEq;

    /// Determine the branch target
    ///
    /// If [`Self`] refers to a branch instruction, this fn returns the
    /// immediate, which is the branch target relative to this instruction.
    /// Returns `None` if [`Self`] does not refer to a (known) branch
    /// instruction. Jump instructions are not considered branch instructions.
    fn branch_target(&self) -> Option<i16>;

    /// Determine the inferable jump target
    ///
    /// If [`Self`] refers to a jump instruction that in itself determines the
    /// jump target, this fn returns that target relative to this instruction.
    /// Returns `None` if [`Self`] does not refer to a (known) jump instruction
    /// or if the branch target cannot be inferred based on the instruction
    /// alone.
    ///
    /// For example, a `jalr` instruciton's target will never be considered
    /// inferable unless the source register is the `zero` register, even if it
    /// is preceeded directly by `auipc` and `addi` instructions defining a
    /// constant jump target.
    ///
    /// Branch instructions are not considered jump instructions.
    fn inferable_jump_target(&self) -> Option<i32>;

    /// Determine the uninferable jump target
    ///
    /// If [`Self`] refers to a jump instruction that in itself does not
    /// determine the (relative) jump target, this fn returns the information
    /// neccessary to determine the target in the form of a register number
    /// (first tuple element) and an offset (second tuple element). The jump
    /// target is computed by adding the offset to the contents of the denoted
    /// register.
    ///
    /// Note that a `jalr` instruciton's target will always be considered
    /// uninferable unless the source register is the `zero` register, even if
    /// it is preceeded directly by `auipc` and `addi` instructions defining a
    /// constant jump target. However, callers may be able to infer the jump
    /// target in such situations using statically determined register values.
    ///
    /// Branch instructions are not considered jump instructions.
    fn uninferable_jump_target(&self) -> Option<(Self::Register, i16)>;

    /// Determine the upper immediate
    ///
    /// If [`Self`] refers to an `auipc`, `lui` or other instruction loading an
    /// upper immediate, this fn returns the register the immediate is stored to
    /// (first tuple element) and its effective value after the instruction
    /// retired (second tuple element) under the assumption that the
    /// instruction's address is `pc`.
    fn upper_immediate(&self, pc: u64) -> Option<(Self::Register, u64)>;

    /// Determine whether this instruction returns from a trap
    ///
    /// Returns `true` if [`Self`] refers to one of the (known) special
    /// instructions that return from a trap.
    fn is_return_from_trap(&self) -> bool;

    /// Determine whether this instruction is an `ecall` or `ebreak`
    ///
    /// Returns `true` if this refers to either an `ecall`, `ebreak` or
    /// `c.ebreak`.
    fn is_ecall_or_ebreak(&self) -> bool;

    /// Determine whether this instruction can be considered a function call
    ///
    /// Returns `true` if [`Self`] refers to an instruction that we consider a
    /// function call, that is a jump-and-link instruction with `ra` (the return
    /// address register) as `rd`.
    fn is_call(&self) -> bool;

    /// Determine whether this instruction can be considered a function return
    ///
    /// Returns `true` if [`Self`] refers to an instruction that we consider a
    /// function return, that is a jump register instruction with `ra` (the
    /// return address register) as `rs1`.
    fn is_return(&self) -> bool;

    /// Determin whether this instruction is a branch instruction
    ///
    /// Returns `true` if [`Self`] refers to a branch instruction.
    fn is_branch(&self) -> bool {
        self.branch_target().is_some()
    }

    /// Determin whether this instruction is an inferable jump
    ///
    /// Returns `true` if [`Self`] refers to a jump with a jump target that can
    /// be infered from the instruction lone. See
    /// [`inferable_jump_target`][Self::inferable_jump_target] for details.
    fn is_inferable_jump(&self) -> bool {
        self.inferable_jump_target().is_some()
    }

    /// Determin whether this instruction is an uninferable jump
    ///
    /// Returns `true` if [`Self`] refers to a jump with a jump target that can
    /// not be infered from the instruction lone. See
    /// [`uninferable_jump_target`][Self::uninferable_jump_target] for details.
    fn is_uninferable_jump(&self) -> bool {
        self.uninferable_jump_target().is_some()
    }

    /// Determine whether this instruction causes an uninferable discontinuity
    ///
    /// Returns `true` if [`Self`] refers to an instruction that causes a (PC)
    /// discontinuity with a target that can not be inferred from the
    /// instruction alone. This is the case if the instruction is either
    /// * an [uninferable jump][Self::is_uninferable_jump],
    /// * a [return from trap][Self::is_return_from_trap] or
    /// * an [`ecall` or `ebreak`][Self::is_ecall_or_ebreak].
    fn is_uninferable_discon(&self) -> bool {
        self.is_uninferable_jump() || self.is_return_from_trap() || self.is_ecall_or_ebreak()
    }
}
