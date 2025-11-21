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
