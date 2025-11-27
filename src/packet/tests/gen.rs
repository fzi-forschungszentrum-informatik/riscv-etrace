// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Generator macros for general encoder and decoder tests

macro_rules! bitstream_test {
    ($n:ident, $b:literal, $d:expr $(, $k:ident $v:tt)*) => {
        bitstream_test!([$n, $b, $d] (Builder::new()) $($k $v)*);
    };
    ($b:tt ($c:expr) params { $($pk:ident: $pv:expr),* } $($k:ident $v:tt)*) => {
        bitstream_test!(
            $b
            ($c)
            params (&config::Parameters { $($pk: $pv,)* ..Default::default() })
            $($k $v)*
        );
    };
    ($b:tt ($c:expr) params ($p:expr) $($k:ident $v:tt)*) => {
        bitstream_test!($b ($c.with_params($p)) $($k $v)*);
    };
    ($b:tt ($c:expr) hart_index_width ($w:expr) $($k:ident $v:tt)*) => {
        bitstream_test!($b ($c.with_hart_index_width($w)) $($k $v)*);
    };
    ($b:tt ($c:expr) timestamp_width ($w:expr) $($k:ident $v:tt)*) => {
        bitstream_test!($b ($c.with_timestamp_width($w)) $($k $v)*);
    };
    ($b:tt ($c:expr) trace_type_width ($w:expr) $($k:ident $v:tt)*) => {
        bitstream_test!($b ($c.with_trace_type_width($w)) $($k $v)*);
    };
    ($b:tt ($c:expr) compression ($w:expr) $($k:ident $v:tt)*) => {
        bitstream_test!($b ($c.with_compression($w)) $($k $v)*);
    };
    ([$n:ident, $b:literal, $d:expr] ($c:expr)) => {
        mod $n {
            use super::*;

            #[test]
            fn decode() {
                let mut decoder = $c.decoder($b);
                assert_eq!(Decode::decode(&mut decoder), Ok($d));
            }

            #[test]
            fn encode() {
                let mut buffer = alloc::vec::Vec::new();
                buffer.resize($b.len(), 0);
                let mut encoder = $c.encoder(buffer.as_mut());
                encoder.encode(&$d).expect("Could not encode item");
                let uncommitted = encoder.uncommitted();
                let len = buffer.len() - uncommitted;
                assert_eq!(&buffer[..len], $b.as_ref());
            }
        }
    };
}
