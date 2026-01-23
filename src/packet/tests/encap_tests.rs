// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Tets related to RISC-V Encapsulation packets
use super::*;

#[test]
fn encap_stop() {
    let mut decoder = Builder::new().decoder(b"\x00\x00\x00\x00");
    for _ in 0..4 {
        assert_eq!(
            decoder.decode::<encap::Packet>(),
            Ok(encap::Packet::NullIdle { flow: 0 }),
        );
    }
    assert_eq!(decoder.bytes_left(), 0, "Not at end of buffer");
    assert_eq!(
        decoder.decode::<encap::Packet>(),
        Err(Error::InsufficientData(NonZeroUsize::MIN)),
    );
}

// sync::Context packet; timestamp: 8D; srcId: 31h, header: extend:1, flow: 10,
// length: 01001 -> 1100 | 1001 = C9 9 bytes payload
//
// $ Note
//
// To decode encap packet with timestamp & srcId, harte_index_width and
// timestamp_width need to be defined otherwise assumed as 0
bitstream_test!(
    normal_support,
    b"\xC9\x31\x8D\x73\x00\x00\x00\x00\x19\x41\x00\x08",
    encap::Packet::from(
        encap::Normal::new(
            2,
            0x31,
            payload::Payload::InstructionTrace(
                sync::Start {
                    branch: true,
                    ctx: sync::Context {
                        privilege: types::Privilege::Machine,
                        time: None,
                        context: 0,
                    },
                    address: 536937572
                }
                .into()
            )
        )
        .with_timestamp(0x8D)
    ),
    params(&PARAMS_32),
    timestamp_width(1),
    hart_index_width(8)
);

bitstream_test!(
    normal_support_small_srcid,
    b"\xCA\xD3\x38\x07\x00\x00\x00\x90\x11\x04\x80\x00",
    encap::Packet::from(
        encap::Normal::new(
            2,
            3,
            payload::Payload::InstructionTrace(
                sync::Start {
                    branch: true,
                    ctx: sync::Context {
                        privilege: types::Privilege::Machine,
                        time: None,
                        context: 0,
                    },
                    address: 536937572
                }
                .into()
            )
        )
        .with_timestamp(0x8D)
    ),
    params(&PARAMS_32),
    timestamp_width(1),
    hart_index_width(4)
);

// header reverse: 0010 | 0000, srdId: 0001 | 0000;
bitstream_test!(
    null_idle,
    b"\x20",
    encap::Packet::<payload::Payload>::NullIdle { flow: 1 },
    params(&PARAMS_32),
    hart_index_width(8)
);

// header reverse: 1110 | 0000; timestamp: 0001 | 1001
bitstream_test!(
    null_align,
    b"\xE0",
    encap::Packet::<payload::Payload>::NullAlign { flow: 3 },
    params(&PARAMS_32),
    timestamp_width(1)
);
