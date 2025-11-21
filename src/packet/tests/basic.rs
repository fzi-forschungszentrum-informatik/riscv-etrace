// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Basic decoder tests
use super::*;

macro_rules! basic_test {
    ($n:ident, $b:literal, $($t:tt)*) => {
        #[test]
        fn $n() {
            let mut decoder = Builder::new().build($b);
            $(decode_test!(decoder, $t);)*
        }
    };
}

macro_rules! decode_test {
    ($d:ident, (bits $i:literal, $v:expr $(, $p:literal)?)) => {
        assert_eq!($d.read_bits($i), Ok($v));
        $(assert_eq!($d.byte_pos(), $p);)?
    };
    ($d:ident, (bit $v:expr $(, $p:literal)?)) => {
        assert_eq!($d.read_bit(), Ok($v));
        $(assert_eq!($d.byte_pos(), $p);)?
    };
    ($d:ident, (diff $v:expr $(, $p:literal)?)) => {
        assert_eq!($d.read_differential_bit(), Ok($v));
        $(assert_eq!($d.byte_pos(), $p);)?
    };
}

basic_test!(
    u64_values,
    b"\x5f\x5f\x92\xf1\xf0\xf0\xf0\xf0\xf0\xff\x7f\x01\x00\x00\x00\x00\x00\x00\xf0",
    (bits 6, 0b011111u64, 0)
    (bits 2, 0b01u64, 1)
    (bits 6, 0b011111u64, 1)
    (bits 10, 0b1001001001u64, 3)
    (bits 62, 0x3FFF_F0F0_F0F0_F0F1u64, 10)
    (bits 64, 0xC000_0000_0000_0005u64, 18)
);

basic_test!(
    i64_values,
    b"\xd0",
    (bits 1, 0i64)
    (bits 64, -24i64)
);

basic_test!(
    decompress,
    b"\xff",
    (bits 64, u64::MAX)
    (bits 64, u64::MAX)
    (bits 64, u64::MAX)
    (bits 64, u64::MAX)
);

basic_test!(
    bool_bits,
    b"\x55",
    (bit true)
    (bit false)
    (bit true)
    (bit false)
    (bit true)
    (bit false)
    (bit true)
    (bit false)
);

basic_test!(
    diff_bits,
    b"\x20\xfd",
    (bits 6, 0x20u8)
    (diff true)
    (diff false)
    (diff true)
    (diff true)
    (diff true)

);

basic_test!(
    missing_msb_shift_is_correct,
    b"\x00\xe1",
    (bits 6, 0i64)
    (bits 63, -124i64)
);
