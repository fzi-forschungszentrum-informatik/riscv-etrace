// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

extern crate alloc;

mod basic;
mod encap_tests;
mod parts;

use super::*;

use core::num::{NonZeroU8, NonZeroUsize};

use crate::types::{self, branch};

use decoder::Decode;
use payload::{AddressInfo, InstructionTrace};

macro_rules! bitstream_test {
    ($n:ident, $b:literal, $d:expr) => {
        bitstream_test!($n, $b, $d, &Default::default());
    };
    ($n:ident, $b:literal, $d:expr, $c:expr) => {
        #[test]
        fn $n() {
            let mut decoder = Builder::new().with_params($c).decoder($b);
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
    branches,
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

/*
Decoded packet: Packet { trace_type: 2, time_tag: None, hart: 0, payload: [115, 0, 0, 0, 0, 25, 65, 0, 8], .. }
Payload: InstructionTrace(Synchronization(Start(Start { branch: true, ctx: Context { privilege: Machine, time: None, context: Some(0) }, address: 536937572 })))
*/
bitstream_test!(
    decode_instruction_trace_sync_payload,
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
        address: -0x204,
        notify: false,
        updiscon: false,
        irdepth: None
    }),
    &PARAMS_64
);

// Ok(Synchronization(Support(Support { ienable: true, encoder_mode: BranchTrace, qual_status: TraceLost, ioptions: ReferenceIOptions { implicit_return: false, implicit_exception: false, full_address: false, jump_target_cache: false, branch_prediction: false }, denable: false, dloss: false, doptions: ReferenceDOptions { no_address: false, no_data: false, full_address: false, full_data: false } })))
bitstream_test!(
    decode_qualstat_trace_lost,
    b"\x9F\x00",
    InstructionTrace::Synchronization(sync::Synchronization::Support(sync::Support {
        ienable: true,
        encoder_mode: sync::EncoderMode::BranchTrace,
        qual_status: sync::QualStatus::TraceLost,
        ioptions: unit::ReferenceIOptions {
            implicit_return: false,
            implicit_exception: false,
            full_address: false,
            jump_target_cache: false,
            branch_prediction: false
        },
        denable: false,
        dloss: false,
        doptions: unit::ReferenceDOptions {
            no_address: false,
            no_data: false,
            full_address: false,
            full_data: false
        }
    })),
    &PARAMS_32
);

bitstream_test!(
    decode_qualstat_ended_ntr,
    b"\xDF\x00",
    InstructionTrace::Synchronization(sync::Synchronization::Support(sync::Support {
        ienable: true,
        encoder_mode: sync::EncoderMode::BranchTrace,
        qual_status: sync::QualStatus::EndedNtr,
        ioptions: unit::ReferenceIOptions {
            implicit_return: false,
            implicit_exception: false,
            full_address: false,
            jump_target_cache: false,
            branch_prediction: false
        },
        denable: false,
        dloss: false,
        doptions: unit::ReferenceDOptions {
            no_address: false,
            no_data: false,
            full_address: false,
            full_data: false
        }
    })),
    &PARAMS_32
);

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
