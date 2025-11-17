// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Types and utilities related to widths

use core::num::NonZeroU8;

use crate::config::Parameters;

/// Widths of various payload fields
#[derive(Copy, Clone)]
pub struct Widths {
    pub cache_index: u8,
    pub context: Option<NonZeroU8>,
    pub time: Option<NonZeroU8>,
    pub ecause: NonZeroU8,
    pub format0_subformat: u8,
    pub iaddress_lsb: NonZeroU8,
    pub iaddress: NonZeroU8,
    pub privilege: NonZeroU8,
    pub stack_depth: Option<NonZeroU8>,
}

impl Default for Widths {
    fn default() -> Self {
        (&Parameters::default()).into()
    }
}

impl From<&Parameters> for Widths {
    fn from(params: &Parameters) -> Self {
        let stack_depth = params.return_stack_size_p
            + params.call_counter_size_p
            + if params.return_stack_size_p > 0 { 1 } else { 0 };
        Self {
            cache_index: params.cache_size_p,
            context: (!params.nocontext_p).then_some(params.context_width_p),
            time: (!params.notime_p).then_some(params.time_width_p),
            ecause: params.ecause_width_p,
            format0_subformat: params.f0s_width_p,
            iaddress_lsb: params.iaddress_lsb_p,
            iaddress: params.iaddress_width_p,
            privilege: params.privilege_width_p,
            stack_depth: NonZeroU8::new(stack_depth),
        }
    }
}
