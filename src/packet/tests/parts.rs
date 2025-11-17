// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Tests focussing on extraction of specialized parts in particular
use super::*;

use util::read_implicit_return;

#[test]
fn implicit_return_test_none() {
    let data = b"\x54\x42\x03\x00\x04\x00\x00\x80";

    let builder = Builder::new();
    let mut decoder = builder
        .with_params(&config::Parameters {
            call_counter_size_p: 1,
            ..Default::default()
        })
        .decoder(data);
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
    let mut decoder = builder.decoder(data);
    let result = read_implicit_return(&mut decoder);
    assert!(matches!(result, Err(Error::InsufficientData(_))));
}

#[test]
fn implicit_return_error_depth() {
    // let data = b"";
    let data: &[u8] = &[]; // no bytes at all
    let builder = Builder::new();
    let mut decoder = builder
        .with_params(&config::Parameters {
            call_counter_size_p: 1,
            ..Default::default()
        })
        .decoder(data);
    let result = read_implicit_return(&mut decoder);
    assert!(matches!(result, Err(Error::InsufficientData(_))));
}

macro_rules! branch_taken_test {
    ($name: ident, $data:expr, $params:expr, $expected:expr) => {
        #[test]
        fn $name() {
            let mut decoder = Builder::new().with_params($params).decoder($data);
            let instruction_trace: payload::InstructionTrace =
                Decode::decode(&mut decoder).unwrap();
            let sync_trace: sync::Synchronization = match instruction_trace {
                InstructionTrace::Synchronization(s) => s,
                _ => panic!("expected synchronization packet"),
            };

            assert_eq!(sync_trace.branch_not_taken(), $expected);
        }
    };
}

// Format 3 subformat 0 - Synchronisation; 1100; first 2 hex:  0110 | 0011; last 0 in 0110,  indicates branch is taken therefore false
branch_taken_test!(
    sync_start_format,
    b"\x63\x00\x00\x00\x00\x19\x41\x00\x08",
    &PARAMS_32,
    Some(false)
);
// Format 3 subformat 1 - Trap; 1101; first 2 hex:  0111 | 0111, expected 1011 for reversed format, but encodes none
branch_taken_test!(
    sync_trap_format,
    b"\x77\x00\x00\x00\x00\x19\x41\x00\x08",
    &PARAMS_32,
    Some(true)
);
// Format 3 subformat 3 - Support; 1111; first 2 hex: 0101 | 1111
branch_taken_test!(
    sync_supp_format,
    b"\x5F\x00\x00\x00\x00\x19\x41\x00\x08",
    &PARAMS_32,
    None
);

macro_rules! as_context_test {
    ($name: ident, $data:expr, $params:expr, $expected:expr) => {
        #[test]
        fn $name() {
            let mut decoder = Builder::new().with_params($params).decoder($data);
            let instruction_trace: payload::InstructionTrace =
                Decode::decode(&mut decoder).unwrap();
            let sync_trace: sync::Synchronization = match instruction_trace {
                InstructionTrace::Synchronization(s) => s,
                _ => panic!("expected synchronization packet"),
            };

            assert_eq!(sync_trace.as_context(), $expected);
        }
    };
}

as_context_test!(
    sync_start_packet,
    b"\x63\x00\x00\x00\x00\x19\x41\x00\x08",
    &PARAMS_32,
    Some(&sync::Context {
        privilege: types::Privilege::Machine,
        time: None,
        context: Some(0)
    })
);

// fmt: 11, subfmt: 10, priv: 11, time: 0, ctx: 0 -> 0011 | 1011 = 3Bh
as_context_test!(
    sync_ctx_packet,
    b"\x3B\x00",
    &PARAMS_32,
    Some(&sync::Context {
        privilege: types::Privilege::Machine,
        time: None,
        context: Some(0)
    })
);

// Fmt: 11, subfmt: 01, branch: 1, priv: 11, time: (non-existent), ctx: 1 -> 1111 | 0111 = F7h
as_context_test!(
    sync_trap_packet,
    b"\xF7\x00\x00\x00\x00\x19\x41\x00\x08",
    &PARAMS_32,
    Some(&sync::Context {
        privilege: types::Privilege::Machine,
        time: None,
        context: Some(1)
    })
);
// Fmt: 11, subfmt: 11, ienable: 1, !enc_mode: 0, qual_stat: 00
as_context_test!(sync_supp_packet, b"\x1F\x00", &PARAMS_32, None);
