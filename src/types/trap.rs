// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Info {
    pub ecause: u64,
    pub tval: u64,
    pub kind: Kind,
}

impl Info {
    pub fn is_interrupt(&self) -> bool {
        self.kind == Kind::Interrupt
    }

    pub fn is_exception(&self) -> bool {
        self.kind == Kind::Exception
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Interrupt,
    Exception,
}
