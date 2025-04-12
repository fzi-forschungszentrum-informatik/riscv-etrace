// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Execution tracing utilities

use crate::instruction::{self, Instruction};
use crate::types::{branch, Privilege};

use super::error::Error;
use super::item::Item;
use super::stack::ReturnStack;

use instruction::binary::Binary;

/// Execution tracing state
#[derive(Clone, Debug)]
pub struct State<S: ReturnStack> {
    /// Current program counter
    pc: u64,

    /// Current instruction
    insn: Instruction,

    /// Previous program counter
    last_pc: u64,

    /// Previous instruction
    last_insn: Instruction,

    /// Address reconstructed from the latest packet
    address: u64,

    /// Sequence of future branches
    branch_map: branch::Map,

    /// Stop condition for the current packet
    stop_condition: StopCondition,

    /// Inferred address that was reported
    inferred_address: Option<u64>,

    /// Current [Privilege] level the core is operating in
    privilege: Privilege,

    /// Stack of (regular) call return addresses
    return_stack: S,

    /// Stack depth communicated by the current packet
    stack_depth: Option<usize>,

    /// Flag indicating whether or not sequential jumps are to be followed
    sequential_jumps: bool,
}

impl<S: ReturnStack> State<S> {
    /// Create a new, initial state for tracing
    pub fn new(return_stack: S, sequential_jumps: bool) -> Self {
        Self {
            pc: 0,
            insn: Default::default(),
            last_pc: 0,
            last_insn: Default::default(),
            address: 0,
            branch_map: Default::default(),
            stop_condition: Default::default(),
            inferred_address: Default::default(),
            privilege: Default::default(),
            return_stack,
            stack_depth: Default::default(),
            sequential_jumps,
        }
    }

    /// Check whether this state is currently fused
    pub fn is_fused(&self) -> bool {
        self.stop_condition == StopCondition::Fused
    }

    /// Retrieve the current [Item] without advancing the state
    pub fn current_item(&self) -> Item {
        Item::new(self.pc, self.insn)
    }

    /// Determine next [Item]
    ///
    /// Returns the next tracing [Item] based on the given address as well as
    /// information within the state if the state is not fused. After
    /// determining the [Item], the stop condition is evaluated and the state is
    /// fused if necessary.
    ///
    /// This roughly corresponds to the loop bodies in`follow_execution_path`
    /// and `process_support` of the reference implementation.
    pub fn next_item<B: Binary>(&mut self, binary: &B) -> Result<Option<Item>, Error<B::Error>> {
        use instruction::Kind;

        if self.is_fused() {
            return Ok(None);
        }

        if let Some(address) = self.inferred_address {
            let (item, end) = self.next_pc(binary, address)?;
            if end {
                self.inferred_address = None;
                if self.stop_condition == StopCondition::NotInferred {
                    self.stop_condition = StopCondition::Fused;
                }
            }

            Ok(Some(item))
        } else {
            let (item, end) = self.next_pc(binary, self.address)?;

            let is_branch = self.insn.kind.and_then(Kind::branch_target).is_some();
            let branch_limit = if is_branch { 1 } else { 0 };

            if end {
                self.stop_condition = StopCondition::Fused;
                if let Some(n) = core::num::NonZeroU8::new(self.branch_map.count())
                    .filter(|n| n.get() > branch_limit)
                {
                    return Err(Error::UnprocessedBranches(n));
                }
            }

            let hit_address_and_branch =
                self.pc == self.address && self.branch_map.count() == branch_limit;
            match self.stop_condition {
                StopCondition::LastBranch if self.branch_map.count() == 1 && is_branch => {
                    self.stop_condition = StopCondition::Fused;
                }
                StopCondition::Address {
                    notify,
                    not_updiscon,
                } if hit_address_and_branch => {
                    if notify {
                        self.stop_condition = StopCondition::Fused;
                    } else if not_updiscon
                        && !self
                            .last_insn
                            .kind
                            .map(Kind::is_uninferable_discon)
                            .unwrap_or(false)
                        && self.stack_depth_matches()
                    {
                        self.inferred_address = Some(self.pc);
                        self.stop_condition = StopCondition::Fused;
                    }
                }
                StopCondition::Sync {
                    privilege: Some(privilege),
                } if hit_address_and_branch
                    && privilege == self.privilege
                    && self
                        .last_insn
                        .kind
                        .map(instruction::Kind::is_return_from_trap)
                        .unwrap_or(false) =>
                {
                    self.stop_condition = StopCondition::Fused;
                }
                StopCondition::Sync { privilege: None } if hit_address_and_branch => {
                    self.stop_condition = StopCondition::Fused;
                }
                _ => (),
            }

            Ok(Some(item))
        }
    }

    /// Determine the exception address for the current instruction
    ///
    /// This roughly corresponds to `exception_address` of the reference
    /// implementation.
    pub fn exception_address<B: Binary>(
        &mut self,
        binary: &B,
        packet_epc: Option<u64>,
    ) -> Result<u64, Error<B::Error>> {
        use instruction::Kind;

        let insn = self.insn;

        if insn.kind.map(Kind::is_uninferable_discon).unwrap_or(false) {
            if let Some(epc) = packet_epc {
                return Ok(epc);
            }
        }

        if insn.kind.map(Kind::is_ecall_or_ebreak).unwrap_or(false) {
            Ok(self.pc)
        } else {
            self.next_pc(binary, self.pc).map(|(i, e)| {
                if e {
                    i.pc().wrapping_add(insn.size.into())
                } else {
                    i.pc()
                }
            })
        }
    }

    /// Create an [Initializer]
    ///
    /// Returns an [Initializer] for this state if the state is fused.
    pub fn initializer<'a, B: Binary>(
        &'a mut self,
        binary: &'a B,
    ) -> Result<Initializer<'a, S, B>, Error<B::Error>> {
        self.is_fused()
            .then_some(Initializer {
                state: self,
                binary,
            })
            .ok_or(Error::UnprocessedInstructions)
    }

    /// Determine the next PC
    ///
    /// Determines the next PC based on the given address as well as information
    /// within the state. Returns the the next [Item] alongside a `bool`
    /// indicating whether any instructions after the following one can be
    /// traced based on the given address and information present in the state
    /// (`false`) or not (`true`).
    ///
    /// This roughly corresponds to `next_pc` of the reference implementation.
    fn next_pc<B: Binary>(
        &mut self,
        binary: &B,
        address: u64,
    ) -> Result<(Item, bool), Error<B::Error>> {
        // The PC right after the current instruction
        let after_pc = self.pc.wrapping_add(self.insn.size.into());

        let (next_pc, end) = self
            .insn
            .kind
            .and_then(|k| {
                self.inferable_jump_target(k)
                    .or_else(|| self.sequential_jump_target(k).map(|t| (t, false)))
                    .or_else(|| self.implicit_return_address(k).map(|t| (t, false)))
                    .map(Ok)
                    .or_else(|| {
                        k.is_uninferable_discon().then(|| {
                            (!matches!(self.stop_condition, StopCondition::LastBranch))
                                .then_some((address, true))
                                .ok_or(Error::UnexpectedUninferableDiscon)
                        })
                    })
                    .or_else(|| self.taken_branch_target(k).transpose())
            })
            .transpose()?
            .unwrap_or((after_pc, false));

        if self
            .insn
            .kind
            .map(instruction::Kind::is_call)
            .unwrap_or(false)
        {
            self.return_stack.push(after_pc);
        }

        self.last_pc = self.pc;
        self.last_insn = self.insn;

        self.pc = next_pc;
        self.insn = binary
            .get_insn(next_pc)
            .map_err(|e| Error::CannotGetInstruction(e, next_pc))?;

        Ok((Item::new(next_pc, self.insn), end))
    }

    /// If the given instruction is an inferable jump, return its target
    ///
    /// Computes and returns the absolute jump target along side a flag
    /// indicating whether the _relative_ target is zero if the given
    /// instruction an inferable jump instruction.
    fn inferable_jump_target(&self, insn: instruction::Kind) -> Option<(u64, bool)> {
        insn.inferable_jump_target()
            .map(|t| (self.pc.wrapping_add_signed(t.into()), t == 0))
    }

    /// If a pair of addresses constitute a sequential jump, compute the target
    ///
    /// This roughly corresponds to a combination of `is_sequential_jump` and
    /// `sequential_jump_target` of the reference implementation.
    fn sequential_jump_target(&self, insn: instruction::Kind) -> Option<u64> {
        use instruction::Kind;

        if !self.sequential_jumps {
            return None;
        }

        let (reg, target) = match self.last_insn.kind? {
            Kind::auipc(d) => (d.rd, self.last_pc.wrapping_add_signed(d.imm.into())),
            Kind::lui(d) => (d.rd, d.imm as u64),
            Kind::c_lui(d) => (d.rd, d.imm as u64),
            _ => return None,
        };

        let (dep, off) = insn.uninferable_jump()?;

        (dep == reg).then_some(target.wrapping_add_signed(off.into()))
    }

    /// If the given instruction is a function return, try to find the return address
    ///
    /// This roughly corresponds to a combination of `is_implicit_return` and
    /// `pop_return_stack` of the reference implementation.
    fn implicit_return_address(&mut self, insn: instruction::Kind) -> Option<u64> {
        if insn.is_return() && self.stack_depth != Some(self.return_stack.depth()) {
            self.return_stack.pop()
        } else {
            None
        }
    }

    /// If the given instruction is a branch and it was taken, return its target
    ///
    /// Computes and returns the absolute branch target along side a flag
    /// indicating whether the _relative_ target is zero if the given
    /// instruction
    /// * is a branch instruciton and
    /// * the branch was taken according to the current branch map.
    ///
    /// This roughly corresponds to a combination of `is_taken_branch` of the
    /// reference implementation.
    fn taken_branch_target<I>(
        &mut self,
        insn: instruction::Kind,
    ) -> Result<Option<(u64, bool)>, Error<I>> {
        let Some(target) = insn.branch_target() else {
            // Not a branch instruction
            return Ok(None);
        };
        let res = self
            .branch_map
            .pop_taken()
            .ok_or(Error::UnresolvableBranch)?
            .then_some((self.pc.wrapping_add_signed(target.into()), target == 0));
        Ok(res)
    }

    /// Determine whether the stack's depth matches the current packet's value
    ///
    /// Returns true if [Self::stack_depth] matches [Self::return_stack]'s
    /// depth or if [Self::stack_depth] is `None`.
    fn stack_depth_matches(&self) -> bool {
        self.stack_depth
            .map(|d| d == self.return_stack.depth())
            .unwrap_or(true)
    }
}

/// [State] initializer
///
/// Allows configuration of [State] and subsequent setting of a [StopCondition].
/// It allows safe configuration as long as it is created for a fused [State].
pub struct Initializer<'a, S: ReturnStack, B: Binary> {
    state: &'a mut State<S>,
    binary: &'a B,
}

impl<S: ReturnStack, B: Binary> Initializer<'_, S, B> {
    /// Set an absolute address
    ///
    /// Set an absolute address and clear the inferred address.
    pub fn set_address(&mut self, address: u64) {
        self.state.address = address;
        self.state.inferred_address = None;
    }

    /// Set a relative address
    ///
    /// Set a relative address and clear the inferred address.
    pub fn set_rel_address(&mut self, address: u64) {
        self.set_address(self.state.address.wrapping_add(address));
    }

    /// Update the inferred address
    ///
    /// If there is an inferred address present in the state, update it to the
    /// current PC. Returns `true` if an inferred address was present, `false`
    /// otherwise.
    pub fn update_inferred(&mut self) -> bool {
        self.state
            .inferred_address
            .as_mut()
            .map(|a| *a = self.state.pc)
            .is_some()
    }

    /// Get a mutable reference to the [State]'s [branch::Map]
    pub fn get_branch_map_mut(&mut self) -> &mut branch::Map {
        &mut self.state.branch_map
    }

    /// Set the privilege
    pub fn set_privilege(&mut self, privilege: Privilege) {
        self.state.privilege = privilege;
    }

    /// Set the stack depth
    pub fn set_stack_depth(&mut self, depth: Option<usize>) {
        self.state.stack_depth = depth;
    }

    /// Set a [StopCondition]
    ///
    /// This operation concludes the configuration.
    pub fn set_condition(self, condition: StopCondition) {
        self.state.stop_condition = condition;
    }

    /// Reset the [State] to the current address
    ///
    /// The current PC is updated to the current address and the current
    /// [Instruction] updated accordingly. Other values are adjusted such that
    /// e.g. sequential jumps are evalued correctly.
    ///
    /// This operation concludes the configuration.
    pub fn reset_to_address(self) -> Result<(), Error<B::Error>> {
        let address = self.state.address;
        let insn = self
            .binary
            .get_insn(address)
            .map_err(|e| Error::CannotGetInstruction(e, address))?;

        self.state.pc = address;
        self.state.insn = insn;
        self.state.last_pc = address;
        self.state.last_insn = Default::default();

        Ok(())
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
