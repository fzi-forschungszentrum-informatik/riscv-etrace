// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
mod gen;

mod chapter12;

use super::*;

use crate::binary;
use crate::decoder::{payload, unit};
use crate::instruction;
use crate::types::branch;

use instruction::{Kind, COMPRESSED, UNCOMPRESSED};
use item::{Context, Item};

trace_test!(
    full_branch_map,
    test_bin_1(),
    start_packet(0x80000010) => {
        (0x80000010, Context::default()),
        (0x80000010, UNCOMPRESSED)
    }
    payload::Branch {
        branch_map: branch::Map::new(31, 0),
        address: None,
    } => {
        (
            31,
            (0x80000014, COMPRESSED),
            (0x80000016, COMPRESSED),
            (0x80000018, COMPRESSED),
            (0x8000001a, COMPRESSED),
            (0x8000001c, Kind::new_bltu(11, 12, -8))
        )
    }
);

trace_test!(
    full_address,
    test_bin_1(),
    sync::Support {
        ienable: true,
        ioptions: unit::ReferenceIOptions {
            full_address: true,
            ..Default::default()
        },
        ..Default::default()
    } => {}
    sync::Start {
        branch: true,
        ctx: Default::default(),
        address: 0x80000000,
    } => {
        (0x80000000, Context::default()),
        (0x80000000, Kind::new_auipc(13, 0x0))
    }
    payload::Branch {
        branch_map: branch::Map::new(1, 1),
        address: Some(payload::AddressInfo {
            address: 0x80000026,
            notify: false,
            updiscon: false,
            irdepth: None,
        }),
    } => {
        (0x80000004, UNCOMPRESSED),
        (0x80000008, UNCOMPRESSED),
        (0x8000000c, Kind::new_auipc(1, 0x0)),
        (0x80000010, UNCOMPRESSED),
        (0x80000014, COMPRESSED),
        (0x80000016, COMPRESSED),
        (0x80000018, COMPRESSED),
        (0x8000001a, COMPRESSED),
        (0x8000001c, Kind::new_bltu(11, 12, -8)),
        (0x80000020, Kind::fence_i),
        (0x80000024, Kind::new_c_jr(1)),
        (0x80000026, UNCOMPRESSED)
    }
    payload::AddressInfo {
        address: 0x80000034,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x8000002a, UNCOMPRESSED),
        (0x8000002e, COMPRESSED),
        (0x80000030, Kind::wfi),
        (0x80000034, Kind::new_c_j(0, -4))
    }
);

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
        (0x8000001c, Kind::new_bltu(11, 12, -8))
    }
    sync::Trap {
        branch: false,
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
    resync,
    test_bin_1(),
    start_packet(0x80000000) => {
        (0x80000000, Context::default()),
        (0x80000000, Kind::new_auipc(13, 0x0))
    }
    start_packet(0x80000010) => {
        (0x80000004, UNCOMPRESSED),
        (0x80000008, UNCOMPRESSED),
        (0x8000000c, Kind::new_auipc(1, 0x0)),
        (0x80000010, Context::default()),
        (0x80000010, UNCOMPRESSED)
    }
);

trace_test!(
    ended_ntr,
    test_bin_1(),
    start_packet(0x80000014) => {
        (0x80000014, Context::default()),
        (0x80000014, COMPRESSED)
    }
    sync::Support {
        ienable: true,
        qual_status: sync::QualStatus::EndedNtr,
        ..Default::default()
    } => {}
);

trace_test!(
    trace_notify,
    test_bin_1(),
    start_packet(0x80000000) => {
        (0x80000000, Context::default()),
        (0x80000000, Kind::new_auipc(13, 0x0))
    }
    payload::AddressInfo {
        address: 0x14,
        notify: true,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000004, UNCOMPRESSED),
        (0x80000008, UNCOMPRESSED),
        (0x8000000c, Kind::new_auipc(1, 0x0)),
        (0x80000010, UNCOMPRESSED),
        (0x80000014, COMPRESSED)
    }
);

// Case 1 described in section 7.6.2 of the spec (version 2.0.3)
trace_test!(
    strange_loop_regular,
    test_bin_jr_loop(),
    start_packet(0x8000000c) => {
        (0x8000000c, Context::default()),
        (0x8000000c, Kind::new_auipc(5, 0x0))
    }
    payload::AddressInfo {
        address: 18,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000010, UNCOMPRESSED),
        (0x80000014, Kind::new_auipc(11, 0)),
        (0x80000018, UNCOMPRESSED),
        (0x8000001c, COMPRESSED),
        (0x8000001e, UNCOMPRESSED)
    }
    payload::AddressInfo {
        address: 4,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000022, COMPRESSED),
        (0x80000024, UNCOMPRESSED),
        (0x80000028, UNCOMPRESSED),
        (0x8000002c, UNCOMPRESSED),
        (0x80000030, UNCOMPRESSED),
        (0x80000034, COMPRESSED),
        (0x80000036, Kind::new_c_jr(5)),
        (0x8000001e, UNCOMPRESSED),
        (0x80000022, COMPRESSED)
    }
);

// Case 2 described in section 7.6.2 of the spec (version 2.0.3)
trace_test!(
    strange_loop_updiscon,
    test_bin_jr_loop(),
    start_packet(0x8000000c) => {
        (0x8000000c, Context::default()),
        (0x8000000c, Kind::new_auipc(5, 0x0))
    }
    payload::AddressInfo {
        address: 18,
        notify: false,
        updiscon: true,
        irdepth: None,
    } => {
        (0x80000010, UNCOMPRESSED),
        (0x80000014, Kind::new_auipc(11, 0)),
        (0x80000018, UNCOMPRESSED),
        (0x8000001c, COMPRESSED),
        (0x8000001e, UNCOMPRESSED),
        (0x80000022, COMPRESSED),
        (0x80000024, UNCOMPRESSED),
        (0x80000028, UNCOMPRESSED),
        (0x8000002c, UNCOMPRESSED),
        (0x80000030, UNCOMPRESSED),
        (0x80000034, COMPRESSED),
        (0x80000036, Kind::new_c_jr(5)),
        (0x8000001e, UNCOMPRESSED)
    }
    sync::Trap {
        branch: true,
        ctx: Default::default(),
        thaddr: true,
        address: 0x80000038,
        info: trap::Info { ecause: 2, tval: Some(0) },
    } => {
        (0x80000022, trap::Info { ecause: 2, tval: Some(0) }),
        (0x80000038, Context::default()),
        (0x80000038, Kind::wfi)
    }
);

// Case 3 described in section 7.6.2 of the spec (version 2.0.3)
trace_test!(
    strange_loop_exception,
    test_bin_jr_loop(),
    start_packet(0x8000000c) => {
        (0x8000000c, Context::default()),
        (0x8000000c, Kind::new_auipc(5, 0x0))
    }
    payload::AddressInfo {
        address: 18,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000010, UNCOMPRESSED),
        (0x80000014, Kind::new_auipc(11, 0)),
        (0x80000018, UNCOMPRESSED),
        (0x8000001c, COMPRESSED),
        (0x8000001e, UNCOMPRESSED)
    }
    sync::Trap {
        branch: true,
        ctx: Default::default(),
        thaddr: true,
        address: 0x80000038,
        info: trap::Info { ecause: 2, tval: Some(0) },
    } => {
        (0x80000022, trap::Info { ecause: 2, tval: Some(0) }),
        (0x80000038, Context::default()),
        (0x80000038, Kind::wfi)
    }
);

// Case 4 described in section 7.6.2 of the spec (version 2.0.3)
trace_test!(
    strange_loop_notify,
    test_bin_jr_loop(),
    start_packet(0x8000000c) => {
        (0x8000000c, Context::default()),
        (0x8000000c, Kind::new_auipc(5, 0x0))
    }
    payload::AddressInfo {
        address: 18,
        notify: true,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000010, UNCOMPRESSED),
        (0x80000014, Kind::new_auipc(11, 0)),
        (0x80000018, UNCOMPRESSED),
        (0x8000001c, COMPRESSED),
        (0x8000001e, UNCOMPRESSED)
    }
    payload::AddressInfo {
        address: 0,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000022, COMPRESSED),
        (0x80000024, UNCOMPRESSED),
        (0x80000028, UNCOMPRESSED),
        (0x8000002c, UNCOMPRESSED),
        (0x80000030, UNCOMPRESSED),
        (0x80000034, COMPRESSED),
        (0x80000036, Kind::new_c_jr(5)),
        (0x8000001e, UNCOMPRESSED)
    }
);

trace_test!(
    fn_calls_baseline,
    test_bin_fncalls(),
    start_packet(0x80000000) => {
        (0x80000000, Context::default()),
        (0x80000000, Kind::new_auipc(13, 0x0))
    }
    payload::AddressInfo {
        address: 0x0e,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000004, UNCOMPRESSED),
        (0x80000008, UNCOMPRESSED),
        (0x8000000c, Kind::new_c_jal(1, 0x14)),
        (0x80000020, COMPRESSED),
        (0x80000022, Kind::new_c_jr(1)),
        (0x8000000e, Kind::new_auipc(13, 0))
    }
    payload::AddressInfo {
        address: 0x12,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000012, Kind::new_jalr(1, 13, 0x12)),
        (0x80000020, COMPRESSED)
    }
    payload::AddressInfo {
        address: 0x16u64.wrapping_sub(0x20),
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000022, Kind::new_c_jr(1)),
        (0x80000016, Kind::new_lui(13,0x80000000u32 as i32))
    }
    payload::AddressInfo {
        address: 0x20-0x16,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x8000001a, Kind::new_jalr(1, 13, 0x20)),
        (0x80000020, COMPRESSED)
    }
    payload::AddressInfo {
        address: 0x1eu64.wrapping_sub(0x20),
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000022, Kind::new_c_jr(1)),
        (0x8000001e, Kind::new_c_j(0, 0x6))
    }
    payload::AddressInfo {
        address: 0x24-0x1e,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000024, Kind::wfi)
    }
);

trace_test!(
    fn_calls_sijump,
    test_bin_fncalls(),
    @params {
        sijump_p: true
    }
    start_packet(0x80000000) => {
        (0x80000000, Context::default()),
        (0x80000000, Kind::new_auipc(13, 0x0))
    }
    payload::AddressInfo {
        address: 0x0e,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000004, UNCOMPRESSED),
        (0x80000008, UNCOMPRESSED),
        (0x8000000c, Kind::new_c_jal(1, 0x14)),
        (0x80000020, COMPRESSED),
        (0x80000022, Kind::new_c_jr(1)),
        (0x8000000e, Kind::new_auipc(13, 0))
    }
    payload::AddressInfo {
        address: 0x16-0x0e,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000012, Kind::new_jalr(1, 13, 0x12)),
        (0x80000020, COMPRESSED),
        (0x80000022, Kind::new_c_jr(1)),
        (0x80000016, Kind::new_lui(13,0x80000000u32 as i32))
    }
    payload::AddressInfo {
        address: 0x1e-0x16,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x8000001a, Kind::new_jalr(1, 13, 0x20)),
        (0x80000020, COMPRESSED),
        (0x80000022, Kind::new_c_jr(1)),
        (0x8000001e, Kind::new_c_j(0, 0x6))
    }
    payload::AddressInfo {
        address: 0x24-0x1e,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000024, Kind::wfi)
    }
);

fn start_packet(address: u64) -> payload::InstructionTrace {
    sync::Start {
        branch: true,
        ctx: Default::default(),
        address,
    }
    .into()
}

fn test_bin_1() -> [(u64, instruction::Instruction); 17] {
    [
        (0x80000000, Kind::new_auipc(13, 0x0).into()),
        (0x80000004, UNCOMPRESSED),
        (0x80000008, UNCOMPRESSED),
        (0x8000000c, Kind::new_auipc(1, 0x0).into()),
        (0x80000010, UNCOMPRESSED),
        // _copy_code
        (0x80000014, COMPRESSED),
        (0x80000016, COMPRESSED),
        (0x80000018, COMPRESSED),
        (0x8000001a, COMPRESSED),
        (0x8000001c, Kind::new_bltu(11, 12, -8).into()),
        (0x80000020, Kind::fence_i.into()),
        (0x80000024, Kind::new_c_jr(1).into()),
        // _entry
        (0x80000026, UNCOMPRESSED),
        (0x8000002a, UNCOMPRESSED),
        (0x8000002e, COMPRESSED),
        // _die
        (0x80000030, Kind::wfi.into()),
        (0x80000034, Kind::new_c_j(0, -4).into()),
    ]
}

fn test_bin_jr_loop() -> [(u64, instruction::Instruction); 15] {
    [
        (0x8000000c, Kind::new_auipc(5, 0).into()),
        (0x80000010, UNCOMPRESSED),
        (0x80000014, Kind::new_auipc(11, 0).into()),
        (0x80000018, UNCOMPRESSED),
        (0x8000001c, COMPRESSED),
        // _loop_entry
        (0x8000001e, UNCOMPRESSED),
        (0x80000022, COMPRESSED),
        (0x80000024, UNCOMPRESSED),
        (0x80000028, UNCOMPRESSED),
        (0x8000002c, UNCOMPRESSED),
        (0x80000030, UNCOMPRESSED),
        (0x80000034, COMPRESSED),
        (0x80000036, Kind::new_c_jr(5).into()),
        // _die
        (0x80000038, Kind::wfi.into()),
        (0x8000003c, Kind::new_c_j(0, -4).into()),
    ]
}

fn test_bin_fncalls() -> [(u64, instruction::Instruction); 13] {
    [
        (0x80000000, Kind::new_auipc(13, 0).into()),
        (0x80000004, UNCOMPRESSED),
        (0x80000008, UNCOMPRESSED),
        (0x8000000c, Kind::new_c_jal(1, 0x14).into()),
        (0x8000000e, Kind::new_auipc(13, 0).into()),
        (0x80000012, Kind::new_jalr(1, 13, 0x12).into()),
        (0x80000016, Kind::new_lui(13, 0x80000000u32 as i32).into()),
        (0x8000001a, Kind::new_jalr(1, 13, 0x20).into()),
        (0x8000001e, Kind::new_c_j(0, 0x6).into()),
        // add
        (0x80000020, COMPRESSED),
        (0x80000022, Kind::new_c_jr(1).into()),
        // _die
        (0x80000024, Kind::wfi.into()),
        (0x80000028, Kind::new_c_j(0, -4).into()),
    ]
}
