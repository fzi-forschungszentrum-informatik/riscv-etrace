// Copyright (C) 2025 FZI Forschungszentrum Informatik
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
