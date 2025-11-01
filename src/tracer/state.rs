// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Execution tracing utilities

use core::num::NonZeroU8;

use crate::binary::Binary;
use crate::instruction::{self, Instruction};
use crate::types::{branch, Privilege};

use super::error::Error;
use super::item::Context;
use super::stack::ReturnStack;

use instruction::info::Info;

/// Execution tracing state
#[derive(Clone, Debug)]
pub struct State<S: ReturnStack, I: Info> {
    /// Current program counter
    pc: u64,

    /// Current instruction
    insn: Instruction<I>,

    /// Previous program counter
    last_pc: u64,

    /// Previous instruction
    last_insn: Instruction<I>,

    /// Address reconstructed from the latest packet
    address: u64,

    /// Sequence of future branches
    branch_map: branch::Map,

    /// Stop condition for the current packet
    stop_condition: StopCondition,

    /// Inferred address that was reported
    inferred_address: Option<u64>,

    /// Current [`Privilege`] level the core is operating in
    privilege: Privilege,

    /// Stack of (regular) call return addresses
    return_stack: S,

    /// Stack depth communicated by the current packet
    stack_depth: Option<usize>,

    /// Width of the address bus
    address_width: NonZeroU8,

    /// Flag indicating whether or not sequential jumps are to be followed
    sequential_jumps: bool,

    /// Flag indicating whether or not to infer fn returns
    implicit_return: bool,
}

impl<S: ReturnStack, I: Info + Clone + Default> State<S, I> {
    /// Create a new, initial state for tracing
    pub fn new(return_stack: S, address_width: NonZeroU8, sequential_jumps: bool) -> Self {
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
            address_width,
            sequential_jumps,
            implicit_return: false,
        }
    }

    /// Check whether this state is currently fused
    pub fn is_fused(&self) -> bool {
        self.stop_condition == StopCondition::Fused
    }

    /// Retrieve the current PC without advancing the state
    pub fn current_pc(&self) -> u64 {
        self.pc
    }

    /// Retrieve the current [`Instruction`] without advancing the state
    pub fn current_insn(&self) -> Instruction<I> {
        self.insn.clone()
    }

    /// Retrieve the previous [`Instruction`] without advancing the state
    pub fn previous_insn(&self) -> &Instruction<I> {
        &self.last_insn
    }

    /// Determine next [`ProtoItem`]
    ///
    /// Returns the next [`ProtoItem`] based on the given address as well as
    /// information within the state if the state is not fused. After
    /// determining the next PC and address, the stop condition is evaluated and
    /// the state is fused if necessary.
    ///
    /// This roughly corresponds to the loop bodies in `follow_execution_path`
    /// and `process_support` of the reference implementation.
    pub fn next_item<B: Binary<I>>(
        &mut self,
        binary: &mut B,
    ) -> Result<Option<ProtoItem<I>>, Error<B::Error>> {
        if self.is_fused() {
            return Ok(None);
        }

        if let Some(address) = self.inferred_address {
            let (pc, insn, end) = self.next_pc(binary, address)?;
            if end {
                self.inferred_address = None;
            }

            Ok(Some((pc, insn, None)))
        } else if self.stop_condition == StopCondition::NotInferred {
            self.stop_condition = StopCondition::Fused;
            Ok(None)
        } else {
            let (pc, insn, end) = self.next_pc(binary, self.address)?;

            let is_branch = self.insn.is_branch();
            let branch_limit = if is_branch { 1 } else { 0 };
            let hit_address_and_branch =
                self.pc == self.address && self.branch_map.count() == branch_limit;
            let ctx = match self.stop_condition {
                StopCondition::LastBranch if self.branch_map.count() == 1 && is_branch => {
                    self.stop_condition = StopCondition::Fused;
                    None
                }
                StopCondition::Address { notify: true, .. } if hit_address_and_branch => {
                    self.stop_condition = StopCondition::Fused;
                    None
                }
                StopCondition::Address {
                    notify: false,
                    not_updiscon: true,
                } if hit_address_and_branch
                    && !self.last_insn.is_uninferable_discon()
                    && self.stack_depth_matches() =>
                {
                    self.inferred_address = Some(self.pc);
                    self.stop_condition = StopCondition::Fused;
                    None
                }
                StopCondition::Sync { context } if hit_address_and_branch => {
                    self.privilege = context.privilege;
                    self.stop_condition = StopCondition::Fused;
                    Some(context)
                }
                _ if end => {
                    self.stop_condition = StopCondition::Fused;
                    if let Some(n) = core::num::NonZeroU8::new(self.branch_map.count())
                        .filter(|n| n.get() > branch_limit)
                    {
                        return Err(Error::UnprocessedBranches(n));
                    }
                    None
                }
                _ => None,
            };

            Ok(Some((pc, insn, ctx)))
        }
    }

    /// Determine the exception address for the current instruction
    ///
    /// This roughly corresponds to `exception_address` of the reference
    /// implementation.
    pub fn exception_address<B: Binary<I>>(
        &mut self,
        binary: &mut B,
        packet_epc: Option<u64>,
    ) -> Result<u64, Error<B::Error>> {
        if self.insn.is_uninferable_discon() {
            if let Some(epc) = packet_epc {
                return Ok(epc);
            }
        }

        if self.insn.is_ecall_or_ebreak() {
            return Ok(self.pc);
        }

        let (pc, insn, end) = self.next_pc(binary, self.pc)?;
        if end {
            Ok(pc.wrapping_add(insn.size.into()))
        } else {
            Ok(pc)
        }
    }

    /// Create an [`Initializer`]
    ///
    /// Returns an [`Initializer`] for this state if the state is fused.
    pub fn initializer<'a, B: Binary<I>>(
        &'a mut self,
        binary: &'a mut B,
    ) -> Result<Initializer<'a, S, B, I>, Error<B::Error>> {
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
    /// within the state. Returns the the next PC and [`Instruction`] alongside
    /// a [`bool`] indicating whether any instructions after the following one
    /// can be traced based on the given address and information present in the
    /// state (`false`) or not (`true`).
    ///
    /// This roughly corresponds to `next_pc` of the reference implementation.
    fn next_pc<B: Binary<I>>(
        &mut self,
        binary: &mut B,
        address: u64,
    ) -> Result<(u64, Instruction<I>, bool), Error<B::Error>> {
        // The PC right after the current instruction
        let after_pc = self.pc.wrapping_add(self.insn.size.into());

        let info = self.insn.info.clone();
        let (mut next_pc, end) = self
            .inferable_jump_target(&info)
            .or_else(|| self.sequential_jump_target(&info).map(|t| (t, false)))
            .or_else(|| self.implicit_return_address(&info).map(|t| (t, false)))
            .map(Ok)
            .or_else(|| {
                info.is_uninferable_discon().then(|| {
                    (!matches!(self.stop_condition, StopCondition::LastBranch))
                        .then_some((address, true))
                        .ok_or(Error::UnexpectedUninferableDiscon)
                })
            })
            .or_else(|| self.taken_branch_target(&info).transpose())
            .transpose()?
            .unwrap_or((after_pc, false));

        next_pc &= !(u64::MAX
            .checked_shl(self.address_width.get().into())
            .unwrap_or(0));

        if self.implicit_return && self.insn.is_call() {
            self.return_stack.push(after_pc);
        }

        self.last_pc = self.pc;
        self.last_insn = self.insn.clone();

        let insn = binary
            .get_insn(next_pc)
            .map_err(|e| Error::CannotGetInstruction(e, next_pc))?;
        self.pc = next_pc;
        self.insn = insn.clone();

        Ok((next_pc, insn, end))
    }

    /// If the given instruction is an inferable jump, return its target
    ///
    /// Computes and returns the absolute jump target along side a flag
    /// indicating whether the _relative_ target is zero if the given
    /// instruction an inferable jump instruction.
    fn inferable_jump_target(&self, insn: &I) -> Option<(u64, bool)> {
        insn.inferable_jump_target()
            .map(|t| (self.pc.wrapping_add_signed(t.into()), t == 0))
    }

    /// If a pair of addresses constitute a sequential jump, compute the target
    ///
    /// This roughly corresponds to a combination of `is_sequential_jump` and
    /// `sequential_jump_target` of the reference implementation.
    fn sequential_jump_target(&self, insn: &I) -> Option<u64> {
        if !self.sequential_jumps {
            return None;
        }

        let (reg, target) = self.last_insn.upper_immediate(self.last_pc)?;
        let (dep, off) = insn.uninferable_jump_target()?;

        (dep == reg).then_some(target.wrapping_add_signed(off.into()))
    }

    /// If the given instruction is a function return, try to find the return address
    ///
    /// This roughly corresponds to a combination of `is_implicit_return` and
    /// `pop_return_stack` of the reference implementation.
    fn implicit_return_address(&mut self, insn: &I) -> Option<u64> {
        if self.implicit_return
            && insn.is_return()
            && self.stack_depth != Some(self.return_stack.depth())
        {
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
    fn taken_branch_target<E>(&mut self, insn: &I) -> Result<Option<(u64, bool)>, Error<E>> {
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
    /// Returns `true` if [`stack_depth`][Self::stack_depth] either matches the
    /// depth of [`return_stack`][Self::return_stack] or is [`None`].
    fn stack_depth_matches(&self) -> bool {
        self.stack_depth
            .map(|d| d == self.return_stack.depth())
            .unwrap_or(true)
    }
}

/// A precursor to a tracer item
///
/// This expands to a regular tracer item, optionally preceeded by a context
/// item.
type ProtoItem<I> = (u64, Instruction<I>, Option<Context>);

/// [`State`] initializer
///
/// An initializer allows the configuration of a [`State`] and the subsequent
/// setting of a [`StopCondition`]. It allows safe configuration as long as it
/// is created for a fused [`State`].
pub struct Initializer<'a, S: ReturnStack, B: Binary<I>, I: Info> {
    state: &'a mut State<S, I>,
    binary: &'a mut B,
}

impl<S: ReturnStack, B: Binary<I>, I: Info + Default> Initializer<'_, S, B, I> {
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
    pub fn set_rel_address(&mut self, mut address: u64) {
        let width = self.state.address_width.get();
        if address >> (width - 1) != 0 {
            address |= u64::MAX.checked_shl(width.into()).unwrap_or(0);
        }
        self.set_address(self.state.address.wrapping_add(address));
    }

    /// Make the state inferred based on the current address
    pub fn set_inferred(&mut self) {
        self.state.inferred_address = Some(self.state.pc);
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

    /// Get a mutable reference to the [`State`]'s [`branch::Map`]
    pub fn get_branch_map_mut(&mut self) -> &mut branch::Map {
        &mut self.state.branch_map
    }

    /// Set the execution context
    pub fn set_context(&mut self, context: Context) {
        self.state.privilege = context.privilege;
    }

    /// Set the stack depth
    pub fn set_stack_depth(&mut self, depth: Option<usize>) {
        self.state.stack_depth = depth;
    }

    /// Set whether or not to infer sequential jumps
    pub fn set_sequential_jumps(&mut self, sequential_jumps: bool) {
        self.state.sequential_jumps = sequential_jumps;
    }

    /// Set whether or not to infer function returns
    pub fn set_implicit_return(&mut self, implicit_return: bool) {
        self.state.implicit_return = implicit_return;
    }

    /// Set a [`StopCondition`]
    ///
    /// This operation concludes the configuration.
    pub fn set_condition(self, condition: StopCondition) {
        self.state.stop_condition = condition;
    }

    /// Reset the [`State`] to the current address
    ///
    /// The current PC is updated to the current address and the current
    /// [`Instruction`] updated accordingly. Other values are adjusted such that
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
    /// Stop at synchonization point (defined in sync packet)
    Sync { context: Context },
    /// The state is already fused and shall not be advanced
    Fused,
}

impl Default for StopCondition {
    fn default() -> Self {
        Self::Fused
    }
}
