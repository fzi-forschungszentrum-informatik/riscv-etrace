// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Generator macros for tracer test

use crate::generator;
use crate::instruction::{self, Instruction};
use crate::tracer::item;
use crate::types::{trap, Context};

use generator::hart2enc::CType;
use generator::step;
use instruction::info::Info;

macro_rules! trace_test {
    ($n:ident, $b:expr, $(@$k:ident $v:tt)* $($p:expr => $i:tt)*) => {
        trace_test_helper!(
            $n,
            tracer::builder().with_binary(binary::from_sorted_map($b)),
            generator::builder(),
            true,
            [$($k $v)*]
            [$($p => $i)*]
        );
    };
}

macro_rules! trace_test_helper {
    ($n:ident, $t:expr, $g:expr, $e:ident, params { $($pk:ident: $pv:expr),* } $c:tt $i:tt) => {
        trace_test_helper!($n, $t, $g, $e, params (&config::Parameters { $($pk: $pv,)* ..Default::default() }) $c $i);
    };
    ($n:ident, $t:expr, $g:expr, $e:ident, params ($p:expr) $c:tt $i:tt) => {
        trace_test_helper!($n, $t.with_params($p), $g.with_params($p), $e, $c $i);
    };
    ($n:ident, $t:expr, $g:expr, $e:ident, address_mode $m:ident $c:tt $i:tt) => {
        trace_test_helper!(
            $n,
            $t.with_address_mode(config::AddressMode::$m),
            $g.with_address_mode(config::AddressMode::$m),
            $e, $c $i
        );
    };
    ($n:ident, $t:expr, $g:expr, $e:ident, implicit_return $r:ident $c:tt $i:tt) => {
        trace_test_helper!($n, $t.with_implicit_return($r), $g.with_implicit_return($r), $e, $c $i);
    };
    ($n:ident, $t:expr, $g:expr, $e:ident, encode $v:ident $c:tt $i:tt) => {
        trace_test_helper!($n, $t, $g, $v, $c $i);
    };
    ($n:ident, $t:expr, $g:expr, $e:ident, [] [$($p:expr => { $($i:tt),* })*]) => {
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

            generator_test!($g, $e, $($p => { $($i),* })*);
        }
    };
    ($n:ident, $t:expr, $g:expr, $e:ident, [$k:ident $v:tt $($kr:ident $vr:tt)*] $i:tt) => {
        trace_test_helper!($n, $t, $g, $e, $k $v [$($kr $vr)*] $i);
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

macro_rules! generator_test {
    ($g:expr, true, $($p:expr => { $($i:tt),* })*) => {
        #[test]
        fn encode() {
            let mut generator: generator::Generator<TestStep> = $g
                .build()
                .expect("Could not build generator");
            let mut converter = ItemConverter::default();
            let packets: [payload::InstructionTrace; _] = [
                $($p.into(),)*
            ];
            let mut packets: &[_] = &packets;
            if let Some(
                payload::InstructionTrace::Synchronization(
                    sync::Synchronization::Support(sync::Support { ioptions, doptions, .. })
                )
            ) = packets.last() {
                generator
                    .begin_qualification(ioptions.clone(), doptions.clone())
                    .expect("Could not start qualification");
            }
            $(
                generator_check_def!(generator, converter, packets, $($i),*);
            )*
            for packet in generator.end_qualification(true) {
                assert_eq!(
                    Some(&packet.expect("Could not drain packet")),
                    packets.split_off_first(),
                );
            }
            assert_eq!(packets, &[]);
        }
    };
    ($g:expr, false, $($p:expr => { $($i:tt),* })*) => {};
}

macro_rules! generator_check_def {
    ($g:ident, $c:ident, $p:ident, ($a:literal, $i:expr $(, $h:ident)*)) => {
        let hints = ItemHints {
            $($h: true,)*
            ..Default::default()
        };
        let event = if hints.sync {
            Some(generator::Event::ReSync)
        } else if hints.notify {
            Some(generator::Event::Notify)
        } else {
            None
        };
        let packet = $c
            .feed_item($a, $i.into(), hints)
            .and_then(|c| $g.process_step(c, event).expect("Could not process step"));
        if let Some(packet) = packet {
            assert_eq!(Some(&packet), $p.split_off_first());
        }
    };
    ($g:ident, $c:ident, $p:ident, [$($i:tt),*; $n:literal]) => {
        (0..$n).for_each(|_| {
            generator_check_def!($g, $c, $p, $($i),*);
        });
    };
    ($g:ident, $c:ident, $p:ident, $($i:tt),*) => {
        $(
            generator_check_def!($g, $c, $p, $i);
        )*
    }
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

/// Helper for constructing [`TestStep`]s from trace item definitions
#[derive(Default)]
pub struct ItemConverter {
    trap: Option<trap::Info>,
    ctype: CType,
    context: Context,
    upper_immediate: Option<<instruction::Kind as Info>::Register>,
}

impl ItemConverter {
    /// Feed a trace item definition, potentially producing a [`TestStep`]
    pub fn feed_item(
        &mut self,
        address: u64,
        kind: item::Kind,
        hints: ItemHints,
    ) -> Option<TestStep> {
        use item::Kind;

        let ctype = self.ctype;
        self.ctype = CType::Unreported;

        let prev_upper_immediate = self.upper_immediate.take();

        match kind {
            Kind::Regular(insn) => {
                self.upper_immediate = insn.upper_immediate(address).map(|(r, _)| r);
                let cycle = TestStep {
                    address,
                    insn: Some(insn),
                    trap: self.trap.take(),
                    ctype,
                    context: self.context,
                    branch_taken: hints.branch_taken,
                    prev_upper_immediate,
                };
                Some(cycle)
            }
            Kind::Trap(info) => {
                self.trap = Some(info);
                None
            }
            Kind::Context(context) => {
                self.context = context;
                if hints.integrate_next {
                    None
                } else {
                    self.trap.take().map(|trap| TestStep {
                        address,
                        insn: None,
                        trap: Some(trap),
                        ctype,
                        context,
                        branch_taken: false,
                        prev_upper_immediate,
                    })
                }
            }
        }
    }
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
