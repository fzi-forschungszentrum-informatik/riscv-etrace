// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Generator macros for tracer test

macro_rules! trace_test {
    ($n:ident, $b:expr, $(@$k:ident $v:tt)* $($p:expr => $i:tt)*) => {
        trace_test!(
            $n,
            @builder { builder().with_binary(binary::from_sorted_map($b)) }
            $(@$k $v)*
            $($p => $i)*
        );
    };
    ($n:ident, @builder { $t:expr } @params { $($pk:ident: $pv:expr),* } $(@$k:ident $v:tt)* $($p:expr => $i:tt)*) => {
        trace_test!(
            $n,
            @builder { $t }
            @params (&config::Parameters { $($pk: $pv,)* ..Default::default() })
            $(@$k $v)*
            $($p => $i)*
        );
    };
    ($n:ident, @builder { $t:expr } @params ($c:expr) $(@$k:ident $v:tt)* $($p:expr => $i:tt)*) => {
        trace_test!($n, @builder { $t.with_params($c) } $(@$k $v)* $($p => $i)*);
    };
    ($n:ident, @builder { $t:expr } $($p:expr => { $($i:tt),* })*) => {
        #[test]
        fn $n() {
            let mut tracer: Tracer<_> = $t.build().expect("Could not build tracer");
            $(
                let payload: InstructionTrace = $p.into();
                tracer.process_te_inst(&payload).expect("Could not process packet");
                trace_check_def!(tracer, $($i),*);
                assert_eq!(tracer.next(), None);
            )*
        }
    };
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
