// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Tets related to RISC-V Encapsulation packets
use super::*;

#[test]
fn encap_stop() {
    let mut decoder = Builder::new().decoder(b"\x00\x00\x00\x00");
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

/* sync::Context packet; timestamp: 8D; srcId: 31h, header: extend:1, flow: 10,
length: 01001 -> 1100 | 1001 = C9 9 bytes payload */
#[test]
fn decode_packet() {
    let data = b"\xC9\x31\x8D\x73\x00\x00\x00\x00\x19\x41\x00\x08";
    // For context: To decode encap packet with timestamp & srcId, harte_index_width and timestamp_width need to be defined otherwise assumed as 0
    let mut decoder = Builder::new()
        .with_params(&PARAMS_32)
        .with_timestamp_width(1)
        .with_hart_index_width(8)
        .decoder(data);
    let encap_packet: encap::Packet<_> = Decode::decode(&mut decoder).unwrap();
    assert_eq!(encap_packet.flow(), 2);
    let normal_encap = encap_packet.into_normal().unwrap();
    assert_eq!(normal_encap.flow(), 2);
    assert_eq!(normal_encap.src_id(), 0x31);
    assert_eq!(normal_encap.timestamp(), Some(0x8D));
    assert_eq!(
        normal_encap.decode_payload().unwrap(),
        payload::Payload::InstructionTrace(InstructionTrace::Synchronization(
            sync::Synchronization::Start(sync::Start {
                branch: true,
                ctx: sync::Context {
                    privilege: types::Privilege::Machine,
                    time: None,
                    context: Some(0)
                },
                address: 536937572
            })
        )),
    );
}

// header reverse: 0010 | 0000, srdId: 0001 | 0000;
#[test]
fn decode_null_idle() {
    let data = b"\x20\x10";
    let mut decoder = Builder::new()
        .with_params(&PARAMS_32)
        .with_hart_index_width(8)
        .decoder(data);
    let encap_data: encap::Packet<_> = Decode::decode(&mut decoder).unwrap();
    assert_eq!(encap_data.flow(), 1);
    assert!(encap_data.is_null());
    assert_eq!(encap_data.into_normal(), None);
}

// header reverse: 1110 | 0000; timestamp: 0001 | 1001
#[test]
fn decode_null_align() {
    let data = b"\xE0\x10";
    let mut decoder = Builder::new()
        .with_params(&PARAMS_32)
        .with_timestamp_width(1)
        .decoder(data);
    let encap_data: encap::Packet<_> = Decode::decode(&mut decoder).unwrap();
    assert_eq!(encap_data.flow(), 3);
}
