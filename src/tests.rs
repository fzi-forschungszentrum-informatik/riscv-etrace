// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
mod test_gen;

mod chapter12;
mod jumps;
mod section762;
mod traps;

use crate::binary;
use crate::config;
use crate::generator;
use crate::instruction;
use crate::packet::{payload, sync};
use crate::tracer;
use crate::types::{Context, Privilege, branch, stack, trap};

use instruction::{COMPRESSED, Kind, UNCOMPRESSED};
use test_gen::{ItemConverter, ItemHints, TestStep};
use tracer::item::Item;

trace_test!(
    full_branch_map,
    test_bin_1(),
    start_packet(0x80000010) => {
        (0x80000010, Context::default()),
        (0x80000010, UNCOMPRESSED)
    }
    payload::Branch {
        branch_map: branch::Map::new(31, 1 << 30),
        address: None,
    } => {
        [
            (0x80000014, COMPRESSED),
            (0x80000016, COMPRESSED),
            (0x80000018, COMPRESSED),
            (0x8000001a, COMPRESSED),
            (0x8000001c, Kind::new_bltu(11, 12, -8));
            31
        ]
    }
    payload::AddressInfo {
        address: 0x20 - 0x10,
        notify: false,
        updiscon: false,
        irdepth: None,
    } => {
        (0x80000020, Kind::fence_i)
    }
);

trace_test!(
    full_address,
    test_bin_1(),
    @address_mode Full
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
        (0x80000010, UNCOMPRESSED, sync)
    }
);

trace_test!(
    sync_with_branches,
    test_bin_1(),
    start_packet(0x80000010) => {
        (0x80000010, Context::default()),
        (0x80000010, UNCOMPRESSED)
    }
    payload::Branch {
        branch_map: branch::Map::new(3, 1 << 2),
        address: Some(payload::AddressInfo {
            address: 0x20 - 0x10,
            notify: false,
            updiscon: false,
            irdepth: None,
        }),
    } => {
        [
            (0x80000014, COMPRESSED),
            (0x80000016, COMPRESSED),
            (0x80000018, COMPRESSED),
            (0x8000001a, COMPRESSED),
            (0x8000001c, Kind::new_bltu(11, 12, -8));
            3
        ],
        (0x80000020, Kind::fence_i)
    }
    start_packet(0x80000024) => {
        (0x80000024, Context::default()),
        (0x80000024, Kind::new_c_jr(1), sync)
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
        (0x80000014, COMPRESSED, notify)
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

// Add tests for ReturnStack for VecStack
#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use crate::tracer::stack::BoxStack;
    use crate::tracer::stack::ReturnStack;
    use crate::tracer::stack::VecStack;
    #[test]
    fn test_vec_stack() {
        let mut s = VecStack::new(4).unwrap();
        assert_eq!(s.max_depth(), 4);
        s.push(50);
        s.push(44);
        s.push(30);
        s.push(35);
        assert_eq!(s.depth(), 4);
        s.push(24);
        assert_eq!(s.depth(), 4);
        s.pop();
        s.pop();
        assert_eq!(s.depth(), 2);
        s.pop();
        s.pop();
        assert_eq!(s.depth(), 0);
    }

    #[test]
    fn test_vec_stack_overflow() {
        let mut vec_stack = VecStack::new(3).unwrap();
        vec_stack.push(33);
        vec_stack.push(0);
        vec_stack.push(1101);
        vec_stack.push(100); // leaves out 33

        assert_eq!(vec_stack.pop(), Some(100));
        assert_eq!(vec_stack.pop(), Some(1101));
        assert_eq!(vec_stack.pop(), Some(0));
        assert_eq!(vec_stack.pop(), None);
    }

    #[test]
    fn test_box_stack() {
        let mut box_stack = BoxStack::new(4).unwrap();
        assert_eq!(box_stack.max_depth(), 4);
        box_stack.push(34);
        box_stack.push(55);
        assert_eq!(box_stack.depth(), 2);
        box_stack.push(100);
        box_stack.push(2000);
        box_stack.push(640);
        assert_eq!(box_stack.depth(), 4);
        for _i in 0..5 {
            box_stack.pop();
        }
        assert_eq!(box_stack.depth(), 0);
    }

    #[test]
    fn test_box_overflow() {
        let mut box_stack = BoxStack::new(3).unwrap();
        for n in 1..10 {
            box_stack.push(n)
        }

        let mut box_stack_copy = box_stack.clone();
        assert_eq!(box_stack.pop(), Some(9));
        assert_eq!(box_stack.pop(), Some(8));
        assert_eq!(box_stack.pop(), Some(7));
        assert_eq!(box_stack.pop(), None);

        assert_eq!(box_stack_copy.pop(), Some(9));
        assert_eq!(box_stack_copy.depth(), 2)
    }
}
