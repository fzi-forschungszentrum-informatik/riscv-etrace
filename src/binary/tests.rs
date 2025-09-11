// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

use super::*;

use crate::instruction;

macro_rules! retrieval_test {
    ($n:ident, $b:expr, $($a:literal $(=> $i:expr)?),*) => {
        #[test]
        fn $n() {
            let mut binary = $b;
            $(
                retrieval_test!(binary, $a $(, $i)?);
            )*
        }
    };
    ($b:ident, $a:literal, $i:expr) => {
        assert_eq!($b.get_insn($a), $i);
    };
    ($b:ident, $a:literal) => {
        assert_eq!($b.get_insn($a), Err(Miss::miss($a)));
    };
}

retrieval_test!(
    segment,
    from_segment(
        b"\x97\x02\x00\x00\xff\x00\x00\x00\x73\x25\x40\xf1\x83\xb2\x82\x01\x67\x80\x02\x00",
        instruction::base::Set::Rv64I,
    ),
    0x00 => Ok(instruction::Kind::new_auipc(5, 0).into()),
    0x04 => Err(error::SegmentError::InvalidInstruction),
    0x08 => Ok(instruction::UNCOMPRESSED),
    0x0c => Ok(instruction::UNCOMPRESSED),
    0x10 => Ok(instruction::Kind::new_jalr(0, 5, 0).into()),
    0x14
);

retrieval_test!(
    simple_map,
    from_sorted_map([
        (0x1000, instruction::UNCOMPRESSED),
        (0x1004, instruction::UNCOMPRESSED),
    ]),
    0x0,
    0x1000 => Ok(instruction::UNCOMPRESSED),
    0x1004 => Ok(instruction::UNCOMPRESSED),
    0x1008
);

retrieval_test!(
    multi,
    Multi::new([
        from_sorted_map([
            (0x1000, instruction::UNCOMPRESSED),
            (0x1004, instruction::UNCOMPRESSED),
        ]),
        from_sorted_map([
            (0x2000, instruction::UNCOMPRESSED),
            (0x2004, instruction::UNCOMPRESSED),
        ]),
    ]),
    0x0,
    0x1000 => Ok(instruction::UNCOMPRESSED),
    0x1004 => Ok(instruction::UNCOMPRESSED),
    0x2000 => Ok(instruction::UNCOMPRESSED),
    0x2004 => Ok(instruction::UNCOMPRESSED),
    0x1000 => Ok(instruction::UNCOMPRESSED),
    0x1008
);

#[cfg(feature = "elf")]
retrieval_test!(
    elf,
    {
        let elf = include_bytes!("testfile.elf");
        let elf = ::elf::ElfBytes::<::elf::endian::LittleEndian>::minimal_parse(elf)
            .expect("Coult not parse ELF file");
        elf::Elf::new(elf).expect("Could not construct binary from ELF file")
    },
    0x0,
    0xa0000000 => Ok(instruction::Kind::new_auipc(13, 0).into()),
    0xa0000004 => Ok(instruction::UNCOMPRESSED),
    0xa0000008 => Ok(instruction::UNCOMPRESSED),
    0xa000000c => Ok(instruction::Kind::new_jal(0, 10).into()),
    0xa0000010 => Ok(instruction::Kind::wfi.into()),
    0xa0000014 => Ok(instruction::Kind::new_c_j(0, -4).into()),
    0xa0000016 => Ok(instruction::Kind::wfi.into()),
    0xa000001a => Ok(instruction::Kind::new_jal(0, -4).into()),
    0xa000001e
);

#[test]
fn binary_from_sorted_map() {
    from_sorted_map([
        (0x1000, instruction::UNCOMPRESSED),
        (0x1004, instruction::UNCOMPRESSED),
    ])
    .expect("Could not create binary");
}

#[test]
fn binary_from_unsorted_map() {
    assert_eq!(
        from_sorted_map([
            (0x1004, instruction::UNCOMPRESSED),
            (0x1000, instruction::UNCOMPRESSED),
        ]),
        None,
    );
}

#[test]
fn binary_from_map() {
    assert_eq!(
        from_map([
            (0x1004, instruction::UNCOMPRESSED),
            (0x1000, instruction::UNCOMPRESSED),
        ]),
        from_sorted_map([
            (0x1000, instruction::UNCOMPRESSED),
            (0x1004, instruction::UNCOMPRESSED),
        ])
        .expect("Could not create binary"),
    );
}
