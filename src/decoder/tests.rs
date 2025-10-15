// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
use super::*;

use crate::types::{self, branch};
use core::num::NonZeroU8;
use payload::AddressInfo;
use util::read_implicit_return;

macro_rules! bitstream_test {
    ($n:ident, $b:literal, $d:expr) => {
        #[test]
        fn $n() {
            let mut decoder = Builder::new().build($b);
            assert_eq!(Decode::decode(&mut decoder), Ok($d));
        }
    };
    ($n:ident, $b:literal, $d:expr, $c:expr) => {
        #[test]
        fn $n() {
            let mut decoder = Builder::new().with_params($c).build($b);
            assert_eq!(Decode::decode(&mut decoder), Ok($d));
        }
    };
    ($n:ident, $b:literal, $d:expr, $( $k:ident : $v:expr ),*) => {
        bitstream_test!($n, $b, $d, &config::Parameters {
            $($k: $v,)*
            ..Default::default()
        });
    };
}

#[test]
fn read_u64() {
    let mut decoder = Builder::new()
        .build(b"\x5f\x5f\x92\xf1\xf0\xf0\xf0\xf0\xf0\xff\x7f\x01\x00\x00\x00\x00\x00\x00\xf0");
    // testing for bit position
    assert_eq!(decoder.read_bits(6), Ok(0b011111u64));
    assert_eq!(decoder.bit_pos, 6);
    assert_eq!(decoder.read_bits(2), Ok(0b01u64));
    assert_eq!(decoder.bit_pos, 8);
    assert_eq!(decoder.read_bits(6), Ok(0b011111u64));
    assert_eq!(decoder.bit_pos, 14);
    // read over byte boundary
    assert_eq!(decoder.read_bits(10), Ok(0b1001001001u64));
    assert_eq!(decoder.bit_pos, 24);
    assert_eq!(decoder.read_bits(62), Ok(0x3FFF_F0F0_F0F0_F0F1u64));
    assert_eq!(decoder.bit_pos, 86);
    assert_eq!(decoder.read_bits(64), Ok(0xC000_0000_0000_0005u64));
    assert_eq!(decoder.bit_pos, 150);
}

#[test]
fn read_i64() {
    let mut decoder = Builder::new().build(b"\xd0\xff\xff\xff\xff\xff\xff\xff\x01");
    assert_eq!(decoder.read_bits(1), Ok(0i64));
    assert_eq!(decoder.read_bits(64), Ok(-24i64));
}

#[test]
fn read_entire_buffer() {
    let mut decoder = Builder::new().build(b"\xff");
    assert_eq!(decoder.read_bits(64), Ok(u64::MAX));
    assert_eq!(decoder.read_bits(64), Ok(u64::MAX));
    assert_eq!(decoder.read_bits(64), Ok(u64::MAX));
    assert_eq!(decoder.read_bits(64), Ok(u64::MAX));
}

#[test]
fn read_bool_bits() {
    let mut decoder = Builder::new().build(b"\x55");
    assert_eq!(decoder.read_bit(), Ok(true));
    assert_eq!(decoder.read_bit(), Ok(false));
    assert_eq!(decoder.read_bit(), Ok(true));
    assert_eq!(decoder.read_bit(), Ok(false));
    assert_eq!(decoder.read_bit(), Ok(true));
    assert_eq!(decoder.read_bit(), Ok(false));
    assert_eq!(decoder.read_bit(), Ok(true));
    assert_eq!(decoder.read_bit(), Ok(false));
}

#[test]
fn missing_msb_shift_is_correct() {
    let mut decoder = Builder::new().build(b"\x00\xe1\xff\xff\xff\xff\xff\xff\x3f");
    assert_eq!(decoder.read_bits(6), Ok(0i64));
    // Modelled after read_address call with iaddress_width_p: 64 and iaddress_lsb_p: 1
    assert_eq!(decoder.read_bits(63), Ok(-124i64));
}

// `format` related tests
bitstream_test!(sync_support, b"\x03", format::Sync::Support);
bitstream_test!(sync_start, b"\x00", format::Sync::Start);
bitstream_test!(sync_trap, b"\x01", format::Sync::Trap);
bitstream_test!(sync_ctx, b"\x02", format::Sync::Context);
bitstream_test!(fmt_ex_branch_count, b"\x00", format::Ext::BranchCount, f0s_width_p: 1);
bitstream_test!(fmt_ex_jti, b"\x01", format::Ext::JumpTargetIndex, f0s_width_p: 1);
bitstream_test!(fmt_1, b"\x04", format::Format::Ext(format::Ext::JumpTargetIndex), f0s_width_p: 1);
bitstream_test!(fmt_2, b"\x01", format::Format::Branch, f0s_width_p: 1);
bitstream_test!(fmt_3, b"\x02", format::Format::Addr, f0s_width_p: 1);
bitstream_test!(fmt_4, b"\x07", format::Format::Sync(format::Sync::Trap), f0s_width_p: 1);

// `payload` related tests
bitstream_test!(
    extension_jti_1,
    b"\x00\x7f\x05",
    payload::JumpTargetIndex { index: 768, branch_map: branch::Map::new(31, 10), irdepth: None },
    cache_size_p: 10
);
bitstream_test!(
    extension_jti_2,
    b"\xff\x03",
    payload::JumpTargetIndex { index: 1023, branch_map: Default::default(), irdepth: None },
    cache_size_p: 10
);
bitstream_test!(
    branch,
    b"\x47\x0b",
    payload::Branch {
        branch_map: branch::Map::new(7, 0b101_1010),
        address: Some(AddressInfo { address: 0, notify: false, updiscon: false, irdepth: None }),
    },
    cache_size_p: 10
);
bitstream_test!(
    branch_with_zero_branches,
    b"\x00\x04",
    payload::Branch {
        branch_map: branch::Map::new(31, 32),
        address: None
    }
);
bitstream_test!(
    address_absolute,
    b"\x01\x00\x00\x00\x00\x00\x00\xc0",
    payload::AddressInfo { address: 4, notify: true, updiscon: false, irdepth: None },
    iaddress_width_p: 64.try_into().unwrap(),
    iaddress_lsb_p: 2.try_into().unwrap()

);
bitstream_test!(
    address_differential,
    b"\x01\x00\x00\x00\x00\x00\x00\x80",
    payload::AddressInfo { address: 4, notify: false, updiscon: true, irdepth: None },
    iaddress_width_p: 64.try_into().unwrap(),
    iaddress_lsb_p: 2.try_into().unwrap()

);
bitstream_test!(
    synchronization_start,
    b"\xff",
    sync::Start {
        branch: true,
        ctx: sync::Context { privilege: types::Privilege::Machine, time: None, context: None },
        address: 0xffff_ffff_ffff_fffe,
    },
    iaddress_width_p: 64.try_into().unwrap(),
    iaddress_lsb_p: 1.try_into().unwrap()
);

#[test]
fn encap_stop() {
    let mut decoder = Builder::new().build(b"\x00\x00\x00\x00");
    for _ in 0..4 {
        assert_eq!(
            decoder.decode_encap_packet(),
            Ok(encap::Packet::NullIdle { flow: 0 }),
        );
    }
    assert_eq!(decoder.bytes_left(), 0, "Not at end of buffer");
    assert_eq!(
        decoder.decode_encap_packet(),
        Err(Error::InsufficientData(NonZeroUsize::MIN)),
    );
}

#[test]
fn implicit_return_test_none() {
    let data = b"\x54\x42\x03\x00\x04\x00\x00\x80";

    let builder = Builder::new();
    let mut decoder = builder.build(data);
    decoder.field_widths.stack_depth = Some(NonZeroU8::new(1).unwrap());
    decoder
        .read_bits::<u8>(5)
        .expect("Tried read bit, but failed");
    let result = read_implicit_return(&mut decoder);
    assert_eq!(result, Ok(Some(1)));
}

#[test]
fn implicit_return_test_empty() {
    let data = b"";
    let builder = Builder::new();
    let mut decoder = builder.build(data);
    let result = read_implicit_return(&mut decoder);
    assert!(matches!(result, Err(Error::InsufficientData(_))));
}

#[test]
fn implicit_return_error_depth() {
    // let data = b"";
    let data: &[u8] = &[]; // no bytes at all
    let builder = Builder::new();
    let mut decoder = builder.build(data);
    decoder.field_widths.stack_depth = Some(NonZeroU8::new(16).unwrap());
    let result = read_implicit_return(&mut decoder);
    assert!(matches!(result, Err(Error::InsufficientData(_))));
}

macro_rules! truncate_test {
    ($name: ident, $val:expr, $type:ty, $bytes:expr, $expected:expr) => {
        #[test]
        fn $name() {
            let val: $type = $val;
            assert_eq!(val.truncated($bytes), $expected);
        }
    };
}

truncate_test!(truncate_u16, 0xBEEF, u16, 8, 0xEF);
truncate_test!(truncate_u32, 0xFFBEEF, u32, 16, 0xBEEF);
truncate_test!(truncate_i64, 0xBEEF00FF, i64, 0, 0);

const PARAMS_32: config::Parameters = config::Parameters {
    cache_size_p: 0,
    call_counter_size_p: 0,
    context_width_p: NonZeroU8::new(32).unwrap(),
    time_width_p: NonZeroU8::new(1).unwrap(),
    ecause_width_p: NonZeroU8::new(5).unwrap(),
    f0s_width_p: 0,
    iaddress_lsb_p: NonZeroU8::new(1).unwrap(),
    iaddress_width_p: NonZeroU8::new(32).unwrap(),
    nocontext_p: false,
    notime_p: true,
    privilege_width_p: NonZeroU8::new(2).unwrap(),
    return_stack_size_p: 0,
    sijump_p: false,
};

const PARAMS_64: config::Parameters = config::Parameters {
    cache_size_p: 0,
    call_counter_size_p: 0,
    context_width_p: NonZeroU8::new(32).unwrap(),
    time_width_p: NonZeroU8::new(1).unwrap(),
    ecause_width_p: NonZeroU8::new(5).unwrap(),
    f0s_width_p: 0,
    iaddress_lsb_p: NonZeroU8::new(1).unwrap(),
    iaddress_width_p: NonZeroU8::new(64).unwrap(),
    nocontext_p: false,
    notime_p: true,
    privilege_width_p: NonZeroU8::new(2).unwrap(),
    return_stack_size_p: 0,
    sijump_p: false,
};
/*
Decoded packet: Packet { trace_type: 2, time_tag: None, hart: 0, payload: [115, 0, 0, 0, 0, 25, 65, 0, 8], .. }
Payload: InstructionTrace(Synchronization(Start(Start { branch: true, ctx: Context { privilege: Machine, time: None, context: Some(0) }, address: 536937572 })))
*/
bitstream_test!(
    instruction_trace_sync_payload,
    b"\x73\x00\x00\x00\x00\x19\x41\x00\x08",
    InstructionTrace::Synchronization(sync::Synchronization::Start(sync::Start {
        branch: true,
        ctx: sync::Context {
            privilege: types::Privilege::Machine,
            time: None,
            context: Some(0)
        },
        address: 536937572
    })),
    &PARAMS_32
);

/*
Decoded packet: Packet { trace_type: 2, time_tag: None, hart: 0, payload: [1, 128, 0], .. }
Payload: InstructionTrace(Branch(Branch { branch_map: Map { count: 31, map: 256 }, address: None }))
*/
bitstream_test!(
    decode_instruction_trace_branch_payload,
    b"\x01\x80\x00",
    InstructionTrace::Branch(payload::Branch {
        branch_map: branch::Map::new(31, 256),
        address: None
    },),
    &PARAMS_32
);
/*
Decoded packet: Packet { trace_type: 2, time_tag: None, hart: 0, payload: [250, 251], .. }
Payload: InstructionTrace(Address(AddressInfo { address: 18446744073709551100, notify: false, updiscon: false, irdepth: None }))
*/
bitstream_test!(
    decode_instruction_trace_address_payload,
    b"\xFA\xFB",
    InstructionTrace::Address(AddressInfo {
        address: 18446744073709551100,
        notify: false,
        updiscon: false,
        irdepth: None
    }),
    &PARAMS_64
);
