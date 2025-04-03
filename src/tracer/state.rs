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

    /// Stop condition for the current packet
    pub stop_condition: StopCondition,

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
            stop_condition: Default::default(),
            inferred_address: Default::default(),
            start_of_trace: true,
            privilege: Default::default(),
            return_stack,
            stack_depth: Default::default(),
        }
    }

    /// Check whether this state is currently fused
    pub fn is_fused(&self) -> bool {
        self.stop_condition == StopCondition::Fused
    }

    /// Determine whether the stack's depth matches the current packet's value
    ///
    /// Returns true if [Self::stack_depth] matches [Self::return_stack]'s
    /// depth or if [Self::stack_depth] is `None`.
    pub fn stack_depth_matches(&self) -> bool {
        self.stack_depth
            .map(|d| d == self.return_stack.depth())
            .unwrap_or(true)
    }
}

/// Condition for stopping instruction tracing (for a single packet)
///
/// This type represents various conditions for stopping instruction tracing.
/// They correspond to conditions for breaking the tracing loop in the fns
/// `follow_execution_path` and `process_support` of the reference pseudo-code.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StopCondition {
    /// Stop when instructions/PCs can no longer be inferred
    NotInferred,
    /// Stop at the last branch recorded in the branch map (i.e. don't empty it)
    LastBranch,
    /// Stop when reaching a condition provided by an address packet
    Address { notify: bool, not_updiscon: bool },
    /// Stop when reaching a condition provided by a sync packet
    Sync { privilege: Option<Privilege> },
    /// The state is already fused and shall not be advanced
    Fused,
}

impl Default for StopCondition {
    fn default() -> Self {
        Self::Fused
    }
}
