// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Tests for behaviour described in section 7.6.2 of the E-Trace specification
//!
//! Section 7.6.2 Format 2 notify and updiscon fields of the E-Trace
//! specification (version 2.0.3) describes in some detail perculiarities of the
//! processing of address information found in address and branch packets. It
//! defines four scenarios that need to be distinguished by a tracer.
//!
//! In addition, section 7.5.1 Format 3 subformat 3 qual_status field defines
//! two distinct values for ending a trace, with each value being relevant for a
//! subset of those scenarios.
//!
//! This module tests the tracer's behaviour for each of these four scenarios.

use super::*;

// Scenario 1
trace_test!(
    regular,
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

trace_test!(
    regular_ntr,
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
    sync::Support {
        ienable: true,
        qual_status: sync::QualStatus::EndedNtr,
        ..Default::default()
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

// Scenario 2
trace_test!(
    updiscon,
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

trace_test!(
    updiscon_rep,
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
    sync::Support {
        ienable: true,
        qual_status: sync::QualStatus::EndedRep,
        ..Default::default()
    } => {}
);

trace_test!(
    updiscon_ntr,
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
    sync::Support {
        ienable: true,
        qual_status: sync::QualStatus::EndedNtr,
        ..Default::default()
    } => {}
);

// Scenario 3
trace_test!(
    exception,
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

trace_test!(
    ended_rep,
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
    sync::Support {
        ienable: true,
        qual_status: sync::QualStatus::EndedRep,
        ..Default::default()
    } => {}
);

// Scenario 4
trace_test!(
    notify,
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
        (0x8000001e, UNCOMPRESSED, notify)
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
    notify_rep,
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
        (0x8000001e, UNCOMPRESSED, notify)
    }
    sync::Support {
        ienable: true,
        qual_status: sync::QualStatus::EndedRep,
        ..Default::default()
    } => {}
);

trace_test!(
    notify_ntr,
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
        (0x8000001e, UNCOMPRESSED, notify)
    }
    sync::Support {
        ienable: true,
        qual_status: sync::QualStatus::EndedNtr,
        ..Default::default()
    } => {}
);

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
