// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Tests concerning behaviour around fn calls (and plain jumps)

use super::*;

trace_test!(
    baseline,
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
        address: 0x16 - 0x20,
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
        address: 0x1e - 0x20,
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
    sijump,
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

trace_test!(
    ir_return_stack,
    test_bin_fncalls(),
    @implicit_return true
    @params {
        return_stack_size_p: 2
    }
    start_packet(0x80000000) => {
        (0x80000000, Context::default()),
        (0x80000000, Kind::new_auipc(13, 0x0))
    }
    payload::AddressInfo {
        address: 0x20,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000004, UNCOMPRESSED),
        (0x80000008, UNCOMPRESSED),
        (0x8000000c, Kind::new_c_jal(1, 0x14)),
        (0x80000020, COMPRESSED)
    }
    payload::AddressInfo {
        address: 0x20-0x20,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000022, Kind::new_c_jr(1)),
        (0x8000000e, Kind::new_auipc(13, 0)),
        (0x80000012, Kind::new_jalr(1, 13, 0x12)),
        (0x80000020, COMPRESSED),
        (0x80000022, Kind::new_c_jr(1)),
        (0x80000016, Kind::new_lui(13,0x80000000u32 as i32)),
        (0x8000001a, Kind::new_jalr(1, 13, 0x20)),
        (0x80000020, COMPRESSED)
    }
    payload::AddressInfo {
        address: 0x24-0x20,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000022, Kind::new_c_jr(1)),
        (0x8000001e, Kind::new_c_j(0, 0x6)),
        (0x80000024, Kind::wfi)
    }
);

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
