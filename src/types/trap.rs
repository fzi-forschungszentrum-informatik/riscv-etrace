// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Info {
    pub ecause: u64,
    pub tval: u64,
    pub kind: Kind,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Interrupt,
    Exception,
}
