// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Generator macros for tracer test

use crate::generator;
use crate::instruction::{self, Instruction};
use crate::types::{trap, Context};

use generator::hart2enc::CType;
use generator::step;
use instruction::info::Info;

macro_rules! trace_test {
    ($n:ident, $b:expr, $(@$k:ident $v:tt)* $($p:expr => $i:tt)*) => {
        trace_test_helper!(
            $n,
            tracer::builder().with_binary(binary::from_sorted_map($b)),
            [$($k $v)*]
            [$($p => $i)*]
        );
    };
}

macro_rules! trace_test_helper {
    ($n:ident, $t:expr, params { $($pk:ident: $pv:expr),* } $c:tt $i:tt) => {
        trace_test_helper!($n, $t, params (&config::Parameters { $($pk: $pv,)* ..Default::default() }) $c $i);
    };
    ($n:ident, $t:expr, params ($p:expr) $c:tt $i:tt) => {
        trace_test_helper!($n, $t.with_params($p), $c $i);
    };
    ($n:ident, $t:expr, address_mode $m:ident $c:tt $i:tt) => {
        trace_test_helper!($n, $t.with_address_mode(config::AddressMode::$m), $c $i);
    };
    ($n:ident, $t:expr, implicit_return $r:ident $c:tt $i:tt) => {
        trace_test_helper!($n, $t.with_implicit_return($r), $c $i);
    };
    ($n:ident, $t:expr, [] [$($p:expr => { $($i:tt),* })*]) => {
        mod $n {
            use super::*;

            #[test]
            fn decode() {
                let mut tracer: tracer::Tracer<_, stack::StaticStack<8>> = $t
                    .build()
                    .expect("Could not build tracer");
                $(
                    let payload: payload::InstructionTrace = $p.into();
                    tracer.process_te_inst(&payload).expect("Could not process packet");
                    trace_check_def!(tracer, $($i),*);
                    assert_eq!(tracer.next(), None);
                )*
            }

            #[test]
            fn size_hint() {
                let mut tracer: tracer::Tracer<_, stack::StaticStack<8>> = $t
                    .build()
                    .expect("Could not build tracer");
                $(
                    let payload: payload::InstructionTrace = $p.into();
                    let mut items = trace_item_count!($($i),*);
                    tracer.process_te_inst(&payload).expect("Could not process packet");
                    while items > 0 {
                        let (min, max) = tracer.size_hint();
                        assert_ne!(tracer.next(), None);
                        assert!(min <= items, "Lower bound: {min} > {items}");
                        if let Some(max) = max {
                            assert!(max >= items, "Upper bound: {max} < {items}");
                        }
                        items -= 1;
                    }
                    let (min, max) = tracer.size_hint();
                    assert_eq!(min, 0);
                    assert_ne!(max, Some(0));
                    assert_eq!(tracer.next(), None);
                )*
            }
        }
    };
    ($n:ident, $t:expr, [$k:ident $v:tt $($kr:ident $vr:tt)*] $i:tt) => {
        trace_test_helper!($n, $t, $k $v [$($kr $vr)*] $i);
    }
}

macro_rules! trace_check_def {
    ($t:ident, ($a:literal, $i:expr $(, $h:ident)*)) => {
        assert_eq!($t.next(), Some(Ok(Item::new($a, $i.into()))));
    };
    ($t:ident, [$($i:tt),*; $n:literal]) => {
        (0..$n).for_each(|_| {
            trace_check_def!($t, $($i),*);
        });
    };
    ($t:ident, $($i:tt),*) => {
        $(
            trace_check_def!($t, $i);
        )*
    }
}

macro_rules! trace_item_count {
    (($a:literal, $i:expr $(, $h:ident)*)) => { 1 };
    ([$($i:tt),*; $n:literal]) => { $n * trace_item_count!($($i),*) };
    ($($i:tt),*) => { 0usize $( + trace_item_count!($i) )* };
}

/// Hints attached to individual test items
#[derive(Copy, Clone, Debug, Default)]
pub struct ItemHints {
    /// Issue a sync event on this item
    pub sync: bool,
    /// Issue a notify event on this item
    pub notify: bool,
    /// This branch was taken
    pub branch_taken: bool,
    /// Integrate this item with the next one
    pub integrate_next: bool,
}

/// [`step::Step`] impl for testing
#[derive(Copy, Clone, Debug)]
pub struct TestStep {
    address: u64,
    insn: Option<Instruction>,
    trap: Option<trap::Info>,
    ctype: CType,
    context: Context,
    branch_taken: bool,
    prev_upper_immediate: Option<<instruction::Kind as Info>::Register>,
}

impl step::Step for TestStep {
    fn address(&self) -> u64 {
        self.address
    }

    fn kind(&self) -> step::Kind {
        if let Some(insn) = self.insn {
            let insn_size = insn.size;
            if let Some(info) = self.trap {
                step::Kind::Trap {
                    insn_size: Some(insn_size),
                    info,
                }
            } else {
                step::Kind::from_instruction(insn, self.branch_taken, self.prev_upper_immediate)
            }
        } else {
            step::Kind::Trap {
                insn_size: None,
                info: self.trap.expect("No insn nor trap in cycle"),
            }
        }
    }

    fn ctype(&self) -> CType {
        self.ctype
    }

    fn context(&self) -> Context {
        self.context
    }

    fn refine(&mut self, next: &Self) {
        use instruction::info::Info;

        if let Some(target) = self.insn.branch_target().filter(|_| next.insn.is_some()) {
            self.branch_taken = self.address.wrapping_add_signed(target.into()) == next.address;
        }
    }
}
