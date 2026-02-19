// Copyright (C) 2025, 2026 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Hart to encoder interface types
//!
//! This module provides types that model parts of the interface described in
//! Chatper 4. Hart to encoder interface of the specification.

/// (Instruction) termination type
///
/// This type represents the `itype` defined in Section 4.2. Instruction trace
/// interface of the specification. It is capable to represent both the three
/// and four bit wide variant. Uninferable jumps in `itype3` are mapped to
/// [`JumpType::UnferJump`].
///
/// The type implements `TryFrom<u8>`, allowing conversion from the numerical
/// representations mandated by the specification.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub enum IType {
    /// Other itype
    #[default]
    Other,
    /// Exception
    Exception,
    /// Interrupt
    Interrupt,
    /// Exception or interrupt return
    ExReturn,
    /// Branch
    Branch { taken: bool },
    /// Jump
    Jump(JumpType),
}

impl TryFrom<u8> for IType {
    type Error = u8;

    fn try_from(num: u8) -> Result<Self, Self::Error> {
        match num {
            0 => Ok(Self::Other),
            1 => Ok(Self::Exception),
            2 => Ok(Self::Interrupt),
            3 => Ok(Self::ExReturn),
            4 => Ok(Self::Branch { taken: false }),
            5 => Ok(Self::Branch { taken: true }),
            6 => Ok(JumpType::UnferJump.into()),
            8 => Ok(JumpType::UnferCall.into()),
            9 => Ok(JumpType::InferCall.into()),
            10 => Ok(JumpType::UnferJump.into()),
            11 => Ok(JumpType::InferJump.into()),
            12 => Ok(JumpType::CoRoutineSwap.into()),
            13 => Ok(JumpType::Return.into()),
            14 => Ok(JumpType::UnferOther.into()),
            15 => Ok(JumpType::InferOther.into()),
            n => Err(n),
        }
    }
}

impl From<JumpType> for IType {
    fn from(jump: JumpType) -> Self {
        Self::Jump(jump)
    }
}

/// Jump instruction classification
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum JumpType {
    /// Uninferable function call
    UnferCall,
    /// Inferable function call
    InferCall,
    /// Uninferable jump
    UnferJump,
    /// Inferable jump
    InferJump,
    /// Co-routine swap
    CoRoutineSwap,
    /// Function return
    Return,
    /// Uninferable jump of some other kind
    UnferOther,
    /// Inferable jump of some other kind
    InferOther,
}

impl JumpType {
    /// Determine whether the jump is a function call
    pub fn is_call(self) -> bool {
        matches!(self, Self::UnferCall | Self::InferCall)
    }

    /// Determine whether the jump is a function return
    pub fn is_return(self) -> bool {
        matches!(self, Self::Return)
    }

    /// Determine whether the jump is inferable
    pub fn is_inferable(self) -> bool {
        matches!(self, Self::InferCall | Self::InferJump | Self::InferOther)
    }
}

/// Context change reporting
///
/// This type represents the `ctype` defined in Section 4.2. Instruction trace
/// interface of the specification.
///
/// The type implements `TryFrom<u8>`, allowing conversion from the numerical
/// representations mandated by the specification.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub enum CType {
    /// The change is not reported
    #[default]
    Unreported,
    /// The change is reported imprecisely
    Imprecisely,
    /// The change is reported precisely
    Precisely,
    /// The change is reported as an asynchronous discontinuity
    AsyncDiscon,
}

impl TryFrom<u8> for CType {
    type Error = u8;

    fn try_from(num: u8) -> Result<Self, Self::Error> {
        match num {
            0 => Ok(Self::Unreported),
            1 => Ok(Self::Imprecisely),
            2 => Ok(Self::Precisely),
            3 => Ok(Self::AsyncDiscon),
            n => Err(n),
        }
    }
}
