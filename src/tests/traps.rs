// Copyright (C) 2025, 2026 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

use super::*;

trace_test!(
    exception,
    test_bin_1(),
    start_packet(0x80000016) => {
        (0x80000016, Context::default()),
        (0x80000016, COMPRESSED)
    }
    sync::Trap {
        branch: true,
        ctx: Default::default(),
        thaddr: true,
        address: 0x80000030,
        info: trap::Info { ecause: 2, tval: Some(0) },
    } => {
        (0x80000018, trap::Info { ecause: 2, tval: Some(0) }),
        (0x80000030, Context::default()),
        (0x80000030, Kind::wfi)
    }
    payload::AddressInfo {
        address: 4,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000034, Kind::new_c_j(0, -4))
    }
);

trace_test!(
    exception_with_priv_change,
    test_bin_1(),
    start_packet(0x80000016) => {
        (0x80000016, Context::default()),
        (0x80000016, COMPRESSED)
    }
    sync::Trap {
        branch: true,
        ctx: sync::Context { privilege: Privilege::Supervisor, ..Default::default() },
        thaddr: true,
        address: 0x80000030,
        info: trap::Info { ecause: 2, tval: Some(0) },
    } => {
        (0x80000018, trap::Info { ecause: 2, tval: Some(0) }),
        (0x80000030, Context { privilege: Privilege::Supervisor, ..Default::default() }),
        (0x80000030, Kind::wfi)
    }
    payload::AddressInfo {
        address: 4,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000034, Kind::new_c_j(0, -4))
    }
);

trace_test!(
    exception_after_branch_taken,
    test_bin_1(),
    sync::Start {
        branch: false,
        ctx: Default::default(),
        address: 0x8000001c,
    } => {
        (0x8000001c, Context::default()),
        (0x8000001c, Kind::new_bltu(11, 12, -8), branch_taken)
    }
    sync::Trap {
        branch: true,
        ctx: Default::default(),
        thaddr: true,
        address: 0x80000030,
        info: trap::Info { ecause: 2, tval: Some(0) },
    } => {
        (0x80000014, trap::Info { ecause: 2, tval: Some(0) }),
        (0x80000030, Context::default()),
        (0x80000030, Kind::wfi)
    }
    payload::AddressInfo {
        address: 4,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000034, Kind::new_c_j(0, -4))
    }
);

trace_test!(
    exception_after_branch_not_taken,
    test_bin_1(),
    sync::Start {
        branch: true,
        ctx: Default::default(),
        address: 0x8000001c,
    } => {
        (0x8000001c, Context::default()),
        (0x8000001c, Kind::new_bltu(11, 12, -8))
    }
    sync::Trap {
        branch: true,
        ctx: Default::default(),
        thaddr: true,
        address: 0x80000030,
        info: trap::Info { ecause: 2, tval: Some(0) },
    } => {
        (0x80000020, trap::Info { ecause: 2, tval: Some(0) }),
        (0x80000030, Context::default()),
        (0x80000030, Kind::wfi)
    }
    payload::AddressInfo {
        address: 4,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000034, Kind::new_c_j(0, -4))
    }
);

trace_test!(
    exception_after_updiscon,
    test_bin_1(),
    start_packet(0x80000024) => {
        (0x80000024, Context::default()),
        (0x80000024, Kind::new_c_jr(1))
    }
    sync::Trap {
        branch: true,
        ctx: Default::default(),
        thaddr: false,
        address: 0x80000000,
        info: trap::Info { ecause: 2, tval: Some(0) },
    } => {
        (0x80000000, trap::Info { ecause: 2, tval: Some(0) }),
        (0x80000000, Context::default())
    }
    start_packet(0x80000030) => {
        (0x80000030, Context::default()),
        (0x80000030, Kind::wfi)
    }
    payload::AddressInfo {
        address: 4,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000034, Kind::new_c_j(0, -4))
    }
);

trace_test!(
    double_trap,
    test_bin_1(),
    start_packet(0x80000018) => {
        (0x80000018, Context::default()),
        (0x80000018, COMPRESSED)
    }
    sync::Trap {
        branch: true,
        ctx: Default::default(),
        thaddr: false,
        address: 0x80000030,
        info: trap::Info { ecause: 2, tval: Some(0) },
    } => {
        (0x8000001a, trap::Info { ecause: 2, tval: Some(0) }),
        (0x8000001a, Context::default())
    }
    sync::Trap {
        branch: true,
        ctx: Default::default(),
        thaddr: true,
        address: 0x80000030,
        info: trap::Info { ecause: 2, tval: Some(0) },
    } => {
        (0x80000030, trap::Info { ecause: 2, tval: Some(0) }),
        (0x80000030, Context::default()),
        (0x80000030, Kind::wfi)
    }
    payload::AddressInfo {
        address: 4,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000034, Kind::new_c_j(0, -4))
    }
);

trace_test!(
    interrupt_then_exception,
    test_bin_1(),
    start_packet(0x80000018) => {
        (0x80000018, Context::default()),
        (0x80000018, COMPRESSED)
    }
    sync::Trap {
        branch: true,
        ctx: Default::default(),
        thaddr: false,
        address: 0x80000030,
        info: trap::Info { ecause: 3, tval: None },
    } => {
        (0x80000018, trap::Info { ecause: 3, tval: None }),
        (0x80000018, Context::default())
    }
    sync::Trap {
        branch: true,
        ctx: Default::default(),
        thaddr: true,
        address: 0x80000030,
        info: trap::Info { ecause: 2, tval: Some(0) },
    } => {
        (0x80000030, trap::Info { ecause: 2, tval: Some(0) }),
        (0x80000030, Context::default()),
        (0x80000030, Kind::wfi)
    }
    payload::AddressInfo {
        address: 4,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000034, Kind::new_c_j(0, -4))
    }
);

trace_test!(
    exception_then_interrupt,
    test_bin_1(),
    start_packet(0x80000018) => {
        (0x80000018, Context::default()),
        (0x80000018, COMPRESSED)
    }
    sync::Trap {
        branch: true,
        ctx: Default::default(),
        thaddr: false,
        address: 0x80000030,
        info: trap::Info { ecause: 2, tval: Some(0) },
    } => {
        (0x8000001a, trap::Info { ecause: 2, tval: Some(0) }),
        (0x8000001a, Context::default())
    }
    sync::Trap {
        branch: true,
        ctx: Default::default(),
        thaddr: true,
        address: 0x80000030,
        info: trap::Info { ecause: 3, tval: None },
    } => {
        (0x80000030, trap::Info { ecause: 3, tval: None }),
        (0x80000030, Context::default()),
        (0x80000030, Kind::wfi)
    }
    payload::AddressInfo {
        address: 4,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000034, Kind::new_c_j(0, -4))
    }
);

trace_test!(
    ecall_priv_change,
    ecall(),
    sync::Start {
        branch: true,
        ctx: sync::Context { privilege: Privilege::Supervisor, ..Default::default() },
        address: 0x80000044,
    } => {
        (0x80000044, Context {
            privilege: Privilege::Supervisor,
            ..Default::default()
        }),
        (0x80000044, Kind::ecall)
    }
    sync::Trap {
        branch: true,
        ctx: sync::Context { privilege: Privilege::Machine, ..Default::default() },
        thaddr: true,
        address: 0x80000010,
        info: trap::Info { ecause: 11, tval: Some(0) }
    } => {
        (0x80000044, trap::Info { ecause: 11, tval: Some(0) }),
        (0x80000010, Context { privilege: Privilege::Machine, ..Default::default() }),
        (0x80000010, COMPRESSED)
    }
    payload::Branch {
        branch_map: branch::Map::new(3, 3),
        address: Some(payload::AddressInfo {
            address: 0x3a-0x10,
            notify: false,
            updiscon: false,
            irdepth: None,
        }),
    } => {
        (0x80000012, COMPRESSED),
        (0x80000014, COMPRESSED),
        (0x80000016, UNCOMPRESSED),
        (0x8000001a, COMPRESSED),
        (0x8000001c, Kind::new_beq(10, 11, 0x2e-0x1c)),
        (0x80000020, COMPRESSED),
        (0x80000022, Kind::new_beq(10, 11, 0x2e-0x22)),
        (0x80000026, COMPRESSED),
        (0x80000028, Kind::new_beq(10, 11, 0x2e-0x28)),
        (0x8000002e, UNCOMPRESSED),
        (0x80000032, COMPRESSED),
        (0x80000034, COMPRESSED),
        (0x80000036, UNCOMPRESSED),
        (0x8000003a, Kind::mret)
    }
    sync::Start {
        branch: true,
        ctx: sync::Context { privilege: Privilege::Supervisor, ..Default::default() },
        address: 0x80000048,
    } => {
        (0x80000048, Context {
            privilege: Privilege::Supervisor,
            ..Default::default()
        }),
        (0x80000048, Kind::wfi)
    }
);

trace_test!(
    ecall_same_priv,
    ecall(),
    start_packet(0x80000044) => {
        (0x80000044, Context::default()),
        (0x80000044, Kind::ecall)
    }
    sync::Trap {
        branch: true,
        ctx: Default::default(),
        thaddr: true,
        address: 0x80000010,
        info: trap::Info { ecause: 11, tval: Some(0) }
    } => {
        (0x80000044, trap::Info { ecause: 11, tval: Some(0) }),
        (0x80000010, Context::default()),
        (0x80000010, COMPRESSED)
    }
    payload::Branch {
        branch_map: branch::Map::new(3, 3),
        address: Some(payload::AddressInfo {
            address: 0x48-0x10,
            notify: false,
            updiscon: false,
            irdepth: None,
        }),
    } => {
        (0x80000012, COMPRESSED),
        (0x80000014, COMPRESSED),
        (0x80000016, UNCOMPRESSED),
        (0x8000001a, COMPRESSED),
        (0x8000001c, Kind::new_beq(10, 11, 0x2e-0x1c)),
        (0x80000020, COMPRESSED),
        (0x80000022, Kind::new_beq(10, 11, 0x2e-0x22)),
        (0x80000026, COMPRESSED),
        (0x80000028, Kind::new_beq(10, 11, 0x2e-0x28)),
        (0x8000002e, UNCOMPRESSED),
        (0x80000032, COMPRESSED),
        (0x80000034, COMPRESSED),
        (0x80000036, UNCOMPRESSED),
        (0x8000003a, Kind::mret),
        (0x80000048, Kind::wfi)
    }
);

trace_test!(
    ecall_after_branch,
    ecall(),
    start_packet(0x80000000) => {
        (0x80000000, Context::default()),
        (0x80000000, Kind::new_auipc(13, 0x0))
    }
    payload::AddressInfo {
        address: 0x44,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000004, UNCOMPRESSED),
        (0x80000008, UNCOMPRESSED),
        (0x8000000c, Kind::new_c_j(0, 0x44 - 0x0c)),
        (0x80000044, Kind::ecall)
    }
    sync::Trap {
        branch: true,
        ctx: Default::default(),
        thaddr: true,
        address: 0x80000010,
        info: trap::Info { ecause: 11, tval: Some(0) }
    } => {
        (0x80000044, trap::Info { ecause: 11, tval: Some(0) }),
        (0x80000010, Context::default()),
        (0x80000010, COMPRESSED)
    }
);

fn ecall() -> [(u64, instruction::Instruction); 26] {
    [
        (0x80000000, Kind::new_auipc(13, 0x0).into()),
        (0x80000004, UNCOMPRESSED),
        (0x80000008, UNCOMPRESSED),
        (0x8000000c, Kind::new_c_j(0, 0x44 - 0x0c).into()),
        (0x8000000e, COMPRESSED),
        // _trap
        (0x80000010, COMPRESSED),
        (0x80000012, COMPRESSED),
        (0x80000014, COMPRESSED),
        (0x80000016, UNCOMPRESSED),
        (0x8000001a, COMPRESSED),
        (0x8000001c, Kind::new_beq(10, 11, 0x2e - 0x1c).into()),
        (0x80000020, COMPRESSED),
        (0x80000022, Kind::new_beq(10, 11, 0x2e - 0x22).into()),
        (0x80000026, COMPRESSED),
        (0x80000028, Kind::new_beq(10, 11, 0x2e - 0x28).into()),
        (0x8000002c, Kind::new_c_j(0, 0x3e - 0x2c).into()),
        // _handle
        (0x8000002e, UNCOMPRESSED),
        (0x80000032, COMPRESSED),
        (0x80000034, COMPRESSED),
        (0x80000036, UNCOMPRESSED),
        (0x8000003a, Kind::mret.into()),
        // _die
        (0x8000003e, Kind::wfi.into()),
        (0x80000042, Kind::new_c_j(0, -4).into()),
        // _main
        (0x80000044, Kind::ecall.into()),
        (0x80000048, Kind::wfi.into()),
        (0x8000004c, Kind::new_c_j(0, -4).into()),
    ]
}
