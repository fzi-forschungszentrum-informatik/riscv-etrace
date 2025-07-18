// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
use super::*;

use crate::decoder::payload;
use crate::instruction;
use crate::types::branch;

use instruction::{Kind, COMPRESSED, UNCOMPRESSED};
use item::Item;

/// Test derived from the specification's Chaper 12, examples 1 and 2
#[test]
fn debug_printf() {
    let code: &[(u64, _)] = &[
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
    ];

    let mut tracer: Tracer<_> = Builder::new()
        .with_binary(code)
        .build()
        .expect("Could not build tracer");

    tracer
        .process_te_inst(&start_packet(0x80001a80))
        .expect("Could not process packet");
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x80001a80, UNCOMPRESSED.into())))
    );
    assert_eq!(tracer.next(), None);

    let payload: Payload = payload::AddressInfo {
        address: 0x80001a88 - 0x80001a80,
        notify: false,
        updiscon: false,
        irdepth: None,
    }
    .into();
    tracer
        .process_te_inst(&payload)
        .expect("Could not process packet");
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x80001a84, Kind::new_jal(1, -2316).into()))),
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x80001178, COMPRESSED.into())))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x8000117a, COMPRESSED.into())))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x8000117c, COMPRESSED.into())))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x8000117e, COMPRESSED.into())))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x80001180, Kind::new_c_jr(1).into()))),
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x80001a88, UNCOMPRESSED.into())))
    );
    assert_eq!(tracer.next(), None);
}

/// Test derived from the specification's Chaper 12, example 3
#[test]
fn exitting_from_func_2() {
    let code: &[(u64, _)] = &[
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
    ];

    let mut tracer: Tracer<_> = Builder::new()
        .with_binary(code)
        .build()
        .expect("Could not build tracer");

    tracer
        .process_te_inst(&start_packet(0x800010da))
        .expect("Could not process packet");
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x800010da, COMPRESSED.into())))
    );
    assert_eq!(tracer.next(), None);

    let payload: Payload = payload::Branch {
        branch_map: branch::Map::new(1, 0),
        address: Some(payload::AddressInfo {
            address: 0xab0,
            notify: false,
            updiscon: false,
            irdepth: None,
        }),
    }
    .into();
    tracer
        .process_te_inst(&payload)
        .expect("Could not process packet");
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(
            0x800010dc,
            Kind::new_bge(0, 10, 0x008).into(),
        )))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x800010e4, COMPRESSED.into())))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x800010e6, COMPRESSED.into())))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x800010e8, Kind::new_c_jr(1).into()))),
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x80001b8a, UNCOMPRESSED.into())))
    );
    assert_eq!(tracer.next(), None);
}

/// Test derived from the specification's Chaper 12, example 4
#[test]
fn three_branches() {
    let code: &[(u64, _)] = &[
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
    ];

    let mut tracer: Tracer<_> = Builder::new()
        .with_binary(code)
        .build()
        .expect("Could not build tracer");

    tracer
        .process_te_inst(&start_packet(0x80001110))
        .expect("Could not process packet");
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x80001110, COMPRESSED.into())))
    );
    assert_eq!(tracer.next(), None);

    let payload: Payload = payload::Branch {
        branch_map: branch::Map::new(3, 0b011),
        address: Some(payload::AddressInfo {
            address: 0x148,
            notify: false,
            updiscon: false,
            irdepth: None,
        }),
    }
    .into();
    tracer
        .process_te_inst(&payload)
        .expect("Could not process packet");
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x80001112, COMPRESSED.into())))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x80001114, COMPRESSED.into())))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(
            0x80001116,
            Kind::new_beq(8, 15, 0x028).into(),
        ))),
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x8000111a, Kind::new_c_beqz(8, 0x036).into()))),
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x8000111c, COMPRESSED.into())))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(
            0x8000111e,
            Kind::new_beq(8, 14, 0x040).into(),
        ))),
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x8000115e, COMPRESSED.into())))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x80001160, COMPRESSED.into())))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x80001162, Kind::new_c_jr(1).into()))),
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x80001258, UNCOMPRESSED.into())))
    );
    assert_eq!(tracer.next(), None);
}

#[test]
fn complex() {
    let code: &[(u64, _)] = &[
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
    ];

    let mut tracer: Tracer<_> = Builder::new()
        .with_binary(code)
        .build()
        .expect("Could not build tracer");

    tracer
        .process_te_inst(&start_packet(0x8000121c))
        .expect("Could not process packet");
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x8000121c, COMPRESSED.into())))
    );
    assert_eq!(tracer.next(), None);

    let payload: Payload = payload::Branch {
        branch_map: branch::Map::new(2, 0b10),
        address: Some(payload::AddressInfo {
            address: 0xffff_ffff_ffff_fef4,
            notify: false,
            updiscon: false,
            irdepth: None,
        }),
    }
    .into();
    tracer
        .process_te_inst(&payload)
        .expect("Could not process packet");
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(
            0x8000121e,
            Kind::new_c_beqz(15, 0x02c).into(),
        ))),
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x8000124a, COMPRESSED.into())))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x8000124c, COMPRESSED.into())))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x8000124e, UNCOMPRESSED.into())))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x80001252, COMPRESSED.into())))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x80001254, Kind::new_jal(1, -0x154).into()))),
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x80001100, COMPRESSED.into())))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x80001102, COMPRESSED.into())))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x80001104, COMPRESSED.into())))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x80001106, COMPRESSED.into())))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x80001108, COMPRESSED.into())))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x8000110a, COMPRESSED.into())))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x8000110c, Kind::new_jal(1, -0x014).into()))),
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x800010f8, COMPRESSED.into())))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x800010fa, UNCOMPRESSED.into())))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x800010fe, Kind::new_c_jr(1).into()))),
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(
            0x80001110,
            Kind::new_c_beqz(10, 0x024).into(),
        ))),
    );
    assert_eq!(tracer.next(), None);
}

#[test]
fn full_branch_map() {
    let code: &[(u64, _)] = &[
        (0x80000028, COMPRESSED),
        (0x8000002a, COMPRESSED),
        (0x8000002c, Kind::new_c_beqz(10, -0x004).into()),
        (0x8000002e, COMPRESSED),
    ];

    let mut tracer: Tracer<_> = Builder::new()
        .with_binary(code)
        .build()
        .expect("Could not build tracer");

    tracer
        .process_te_inst(&start_packet(0x80000028))
        .expect("Could not process packet");
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x80000028, COMPRESSED.into())))
    );
    assert_eq!(tracer.next(), None);

    let payload: Payload = payload::Branch {
        branch_map: branch::Map::new(31, 0),
        address: None,
    }
    .into();
    tracer
        .process_te_inst(&payload)
        .expect("Could not process packet");
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(0x8000002a, COMPRESSED.into())))
    );
    assert_eq!(
        tracer.next(),
        Some(Ok(Item::new(
            0x8000002c,
            Kind::new_c_beqz(10, -0x004).into(),
        ))),
    );
    (2..=31).for_each(|_| {
        assert_eq!(
            tracer.next(),
            Some(Ok(Item::new(0x80000028, COMPRESSED.into())))
        );
        assert_eq!(
            tracer.next(),
            Some(Ok(Item::new(0x8000002a, COMPRESSED.into())))
        );
        assert_eq!(
            tracer.next(),
            Some(Ok(Item::new(
                0x8000002c,
                Kind::new_c_beqz(10, -0x004).into(),
            ))),
        );
    });
    assert_eq!(tracer.next(), None);
}

fn start_packet(address: u64) -> payload::Payload {
    sync::Start {
        branch: false,
        ctx: Default::default(),
        address,
    }
    .into()
}
