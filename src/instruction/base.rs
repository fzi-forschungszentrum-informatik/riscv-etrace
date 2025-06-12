// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Base instruction set
//!
//! This module provides definitions for representing RISC-V base instruction
//! set variants such as `RV32I` and utilities for decoding instructions.

/// RISC-V base instruction set variant
///
/// The RISC-V specification(s) define a small set of base instruction sets,
/// such as `RV32I`, and various extensions (such as `M` or `C`). An encoding
/// of any given instruction does not differ between sets of extensions
/// supported, but it may differ between base instruction sets.
#[derive(Copy, Clone, Debug)]
pub enum Set {
    Rv32I,
}
