// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Generator macros for tracer test

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
                let mut tracer: tracer::Tracer<_, tracer::stack::StaticStack<8>> = $t
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
                let mut tracer: tracer::Tracer<_, tracer::stack::StaticStack<8>> = $t
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
    ($t:ident, ($a:literal, $i:expr)) => {
        assert_eq!($t.next(), Some(Ok(Item::new($a, $i.into()))));
    };
    ($t:ident, ($n:literal, $($i:tt),*)) => {
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
    (($a:literal, $i:expr)) => { 1 };
    (($n:literal, $($i:tt),*)) => { $n * trace_item_count!($($i),*) };
    ($($i:tt),*) => { 0usize $( + trace_item_count!($i) )* };
}
