// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Execution tracing utilities

use crate::instruction::Instruction;
use crate::types::{branch, Privilege};

use super::stack::ReturnStack;

/// Execution tracing state
#[derive(Clone, Debug)]
pub struct State<S: ReturnStack> {
    /// Current program counter
    pub pc: u64,

    /// Current instruction
    pub insn: Instruction,

    /// Previous program counter
    pub last_pc: u64,

    /// Previous instruction
    pub last_insn: Instruction,

    /// Address reconstructed from the latest packet
    pub address: u64,

    /// Sequence of future branches
    pub branch_map: branch::Map,

    /// Execution is to stop at the last branch recorded in [Self::branch_map]
    pub stop_at_last_branch: bool,

    /// Inferred address that was reported
    pub inferred_address: Option<u64>,

    /// Flag indicating we're at the start of a trace
    pub start_of_trace: bool,

    /// Current [Privilege] level the core is operating in
    pub privilege: Privilege,

    /// Stack of (regular) call return addresses
    pub return_stack: S,

    /// Stack depth communicated by the current packet
    pub stack_depth: Option<usize>,
}

impl<S: ReturnStack> State<S> {
    /// Create a new, initial state for tracing
    pub fn new(return_stack: S) -> Self {
        Self {
            pc: 0,
            insn: Default::default(),
            last_pc: 0,
            last_insn: Default::default(),
            address: 0,
            branch_map: Default::default(),
            stop_at_last_branch: false,
            inferred_address: Default::default(),
            start_of_trace: true,
            privilege: Default::default(),
            return_stack,
            stack_depth: Default::default(),
        }
    }
}
