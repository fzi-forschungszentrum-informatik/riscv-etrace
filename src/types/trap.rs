// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Info {
    pub ecause: u64,
    pub tval: Option<u64>,
}

impl Info {
    pub fn is_interrupt(&self) -> bool {
        self.tval.is_none()
    }

    pub fn is_exception(&self) -> bool {
        self.tval.is_some()
    }
}
