// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Tracing item

use crate::decoder::sync;
use crate::instruction::{self, info, Instruction};
use crate::types::{trap, Privilege};

/// Tracing item
///
/// A tracing item corresponds to either a traced, retired [`Instruction`] or
/// some other noteworthy event such as a trap.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pc: u64,
    kind: Kind,
}

impl Item {
    /// Create a new item
    pub fn new(pc: u64, kind: Kind) -> Self {
        Self { pc, kind }
    }

    /// Retrieve the PC
    ///
    /// For items signalling a retired [`Instruction`], this fn will return its
    /// address. For exceptions, it will return the EPC. For interrupts, it will
    /// return the PC of the address of the last retired [`Instruction`].
    pub fn pc(&self) -> u64 {
        self.pc
    }

    /// Retrieve the item's [`Kind`]
    pub fn kind(&self) -> &Kind {
        &self.kind
    }

    /// Retrieve the (retired) [`Instruction`]
    pub fn instruction(&self) -> Option<Instruction> {
        match self.kind {
            Kind::Regular(insn) => Some(insn),
            _ => None,
        }
    }

    /// Retrieve the [`trap::Info`] assocaited to this item
    ///
    /// If this item signals a trap, this fn returns the associated
    /// [`trap::Info`]. Otherwise, `None` is returned.
    pub fn trap(&self) -> Option<&trap::Info> {
        match &self.kind {
            Kind::Trap(info) => Some(info),
            _ => None,
        }
    }
}

/// Kind of a tracing [`Item`]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Kind<I: info::Info = Option<instruction::Kind>> {
    /// Signals the retiring of the [`Instruction`] at the [`Item`]'s PC
    Regular(Instruction<I>),
    /// Signals a trap
    ///
    /// In the case of an exception, the [`Item`]'s PC indicated the EPC. In the
    /// case of an interrupt, the PC will point at the last [`Instruction`]
    /// retired before the interrut.
    Trap(trap::Info),
    /// Signals an updated execution context
    ///
    /// The [`Context`] may or may not differ from the last communicated one.
    /// The [`Item`]'s PC is the PC of the first instruction executed (and
    /// retired) after the update, i.e. the PC of the following [`Item`].
    Context(Context),
}

impl<I: info::Info> From<Instruction<I>> for Kind<I> {
    fn from(insn: Instruction<I>) -> Self {
        Self::Regular(insn)
    }
}

impl From<instruction::Kind> for Kind<Option<instruction::Kind>> {
    fn from(insn: instruction::Kind) -> Self {
        Self::Regular(insn.into())
    }
}

impl<I: info::Info> From<trap::Info> for Kind<I> {
    fn from(info: trap::Info) -> Self {
        Self::Trap(info)
    }
}

impl<I: info::Info> From<Context> for Kind<I> {
    fn from(context: Context) -> Self {
        Self::Context(context)
    }
}

/// Execution context
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct Context {
    /// The privilege level under which code is executed
    pub privilege: Privilege,
    /// The context of the execution
    pub context: u64,
}

impl From<&sync::Context> for Context {
    fn from(ctx: &sync::Context) -> Self {
        Self {
            privilege: ctx.privilege,
            context: ctx.context.unwrap_or_default(),
        }
    }
}

impl From<sync::Context> for Context {
    fn from(ctx: sync::Context) -> Self {
        (&ctx).into()
    }
}
