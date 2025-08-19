// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
use super::*;

use crate::binary;
use crate::decoder::payload;
use crate::instruction;
use crate::types::branch;

use instruction::{Kind, COMPRESSED, UNCOMPRESSED};
use item::{Context, Item};

macro_rules! trace_test {
    ($n:ident, $b:expr, $($p:expr => { $($i:tt),* })*) => {
        #[test]
        fn $n() {
            let code = binary::from_sorted_map($b);
            let mut tracer: Tracer<_> = Builder::new()
                .with_binary(code)
                .build()
                .expect("Could not build tracer");
            $(
                let payload: Payload = $p.into();
                tracer.process_te_inst(&payload)
                    .expect("Could not process packet");
                $(
                    trace_check_def!(tracer, $i);
                )*
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
            $(
                trace_check_def!($t, $i);
            )*
        });
    };
}

// Test derived from the specification's Chaper 12, examples 1 and 2
trace_test!(
    debug_printf,
    [
        // debug_printf:
        (0x80001178, COMPRESSED),
        (0x8000117a, COMPRESSED),
        (0x8000117c, COMPRESSED),
        (0x8000117e, COMPRESSED),
        (0x80001180, Kind::new_c_jr(1).into()),
        // main:
        (0x80001a80, UNCOMPRESSED),
        // Call debug_printf
        (0x80001a84, Kind::new_jal(1, -0x90c).into()),
        (0x80001a88, UNCOMPRESSED),
    ],
    start_packet(0x80001a80) => {
        (0x80001a80, Context::default()),
        (0x80001a80, UNCOMPRESSED)
    }
    payload::AddressInfo {
        address: 0x80001a88 - 0x80001a80,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80001a84, Kind::new_jal(1, -2316)),
        (0x80001178, COMPRESSED),
        (0x8000117a, COMPRESSED),
        (0x8000117c, COMPRESSED),
        (0x8000117e, COMPRESSED),
        (0x80001180, Kind::new_c_jr(1)),
        (0x80001a88, UNCOMPRESSED)
    }
);

// Test derived from the specification's Chaper 12, example 3
trace_test!(
    exitting_from_func_2,
    [
        // Func_2:
        (0x800010da, COMPRESSED),
        (0x800010dc, Kind::new_bge(0, 10, 0x008).into()),
        (0x800010e0, COMPRESSED),
        (0x800010e2, COMPRESSED),
        (0x800010e4, COMPRESSED),
        (0x800010e6, COMPRESSED),
        (0x800010e8, Kind::new_c_jr(1).into()),
        // main:
        (0x80001b8a, UNCOMPRESSED),
    ],
    start_packet(0x800010da) => {
        (0x800010da, Context::default()),
        (0x800010da, COMPRESSED)
    }
    payload::Branch {
        branch_map: branch::Map::new(1, 0),
        address: Some(payload::AddressInfo {
            address: 0xab0,
            notify: false,
            updiscon: false,
            irdepth: None,
        }),
    } => {
        (0x800010dc, Kind::new_bge(0, 10, 0x008)),
        (0x800010e4, COMPRESSED),
        (0x800010e6, COMPRESSED),
        (0x800010e8, Kind::new_c_jr(1)),
        (0x80001b8a, UNCOMPRESSED)
    }
);

// Test derived from the specification's Chaper 12, example 4
trace_test!(
    three_branches,
    [
        // Proc_6:
        (0x80001110, COMPRESSED),
        (0x80001112, COMPRESSED),
        (0x80001114, COMPRESSED),
        (0x80001116, Kind::new_beq(8, 15, 0x028).into()),
        (0x8000111a, Kind::new_c_beqz(8, 0x036).into()),
        (0x8000111c, COMPRESSED),
        (0x8000111e, Kind::new_beq(8, 14, 0x040).into()),
        (0x8000115e, COMPRESSED),
        (0x80001160, COMPRESSED),
        (0x80001162, Kind::new_c_jr(1).into()),
        // Proc_1:
        (0x80001258, UNCOMPRESSED),
    ],
    start_packet(0x80001110) => {
        (0x80001110, Context::default()),
        (0x80001110, COMPRESSED)
    }
    payload::Branch {
        branch_map: branch::Map::new(3, 0b011),
        address: Some(payload::AddressInfo {
            address: 0x148,
            notify: false,
            updiscon: false,
            irdepth: None,
        }),
    } => {
        (0x80001112, COMPRESSED),
        (0x80001114, COMPRESSED),
        (0x80001116, Kind::new_beq(8, 15, 0x028)),
        (0x8000111a, Kind::new_c_beqz(8, 0x036)),
        (0x8000111c, COMPRESSED),
        (0x8000111e, Kind::new_beq(8, 14, 0x040)),
        (0x8000115e, COMPRESSED),
        (0x80001160, COMPRESSED),
        (0x80001162, Kind::new_c_jr(1)),
        (0x80001258, UNCOMPRESSED)
    }
);

trace_test!(
    complex,
    [
        // Func_3:
        (0x800010f8, COMPRESSED),
        (0x800010fa, UNCOMPRESSED),
        (0x800010fe, Kind::new_c_jr(1).into()),
        // Proc_6:
        (0x80001100, COMPRESSED),
        (0x80001102, COMPRESSED),
        (0x80001104, COMPRESSED),
        (0x80001106, COMPRESSED),
        (0x80001108, COMPRESSED),
        (0x8000110a, COMPRESSED),
        // Call Func_3
        (0x8000110c, Kind::new_jal(1, -0x014).into()),
        (0x80001110, Kind::new_c_beqz(10, 0x024).into()),
        (0x80001112, COMPRESSED),
        // Proc_1:
        (0x8000121c, COMPRESSED),
        (0x8000121e, Kind::new_c_beqz(15, 0x02c).into()),
        (0x8000124a, COMPRESSED),
        (0x8000124c, COMPRESSED),
        (0x8000124e, UNCOMPRESSED),
        (0x80001252, COMPRESSED),
        // Call Proc_6
        (0x80001254, Kind::new_jal(1, -0x154).into()),
    ],
    start_packet(0x8000121c) => {
        (0x8000121c, Context::default()),
        (0x8000121c, COMPRESSED)
    }
    payload::Branch {
        branch_map: branch::Map::new(2, 0b10),
        address: Some(payload::AddressInfo {
            address: 0xffff_ffff_ffff_fef4,
            notify: false,
            updiscon: false,
            irdepth: None,
        }),
    } => {
        (0x8000121e, Kind::new_c_beqz(15, 0x02c)),
        (0x8000124a, COMPRESSED),
        (0x8000124c, COMPRESSED),
        (0x8000124e, UNCOMPRESSED),
        (0x80001252, COMPRESSED),
        (0x80001254, Kind::new_jal(1, -0x154)),
        (0x80001100, COMPRESSED),
        (0x80001102, COMPRESSED),
        (0x80001104, COMPRESSED),
        (0x80001106, COMPRESSED),
        (0x80001108, COMPRESSED),
        (0x8000110a, COMPRESSED),
        (0x8000110c, Kind::new_jal(1, -0x014)),
        (0x800010f8, COMPRESSED),
        (0x800010fa, UNCOMPRESSED),
        (0x800010fe, Kind::new_c_jr(1)),
        (0x80001110, Kind::new_c_beqz(10, 0x024))
    }
);

trace_test!(
    full_branch_map,
    [
        (0x80000028, COMPRESSED),
        (0x8000002a, COMPRESSED),
        (0x8000002c, Kind::new_c_beqz(10, -0x004).into()),
        (0x8000002e, COMPRESSED),
    ],
    start_packet(0x80000028) => {
        (0x80000028, Context::default()),
        (0x80000028, COMPRESSED)
    }
    payload::Branch {
        branch_map: branch::Map::new(31, 0),
        address: None,
    } => {
        (0x8000002a, COMPRESSED),
        (0x8000002c, Kind::new_c_beqz(10, -0x004)),
        (
            30,
            (0x80000028, COMPRESSED),
            (0x8000002a, COMPRESSED),
            (0x8000002c, Kind::new_c_beqz(10, -0x004))
        )
    }
);

fn start_packet(address: u64) -> payload::Payload {
    sync::Start {
        branch: false,
        ctx: Default::default(),
        address,
    }
    .into()
}
