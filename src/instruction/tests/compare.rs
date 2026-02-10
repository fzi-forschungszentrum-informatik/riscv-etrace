// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[allow(unused_macros)]
macro_rules! compare_test {
    ($n:ident, $t:ty, $b:expr) => {
        mod $n {
            use super::*;

            #[test]
            fn compare_16() {
                compare_infos_16::<_, $t>($b)
            }

            compare_test!(compare_32_0, $b, $t, 0, 29);
            compare_test!(compare_32_1, $b, $t, 1, 29);
            compare_test!(compare_32_2, $b, $t, 2, 29);
            compare_test!(compare_32_3, $b, $t, 3, 29);
            compare_test!(compare_32_4, $b, $t, 4, 29);
            compare_test!(compare_32_5, $b, $t, 5, 29);
            compare_test!(compare_32_6, $b, $t, 6, 29);
            compare_test!(compare_32_7, $b, $t, 7, 29);
        }
    };
    ($n:ident, $b:expr, $t:ty, $i:expr, $o:expr) => {
        #[test]
        fn $n() {
            compare_infos_32::<_, $t>($b, $i, $o);
        }
    };
}

#[cfg(feature = "riscv-isa")]
mod compare_riscv_isa {
    use super::*;

    use info::MakeDecode;

    #[test]
    fn compressed_rv32i() {
        compare_infos_16::<_, riscv_isa::Compressed>(riscv_isa::Target::rv32i_full());
    }

    #[test]
    fn compressed_rv64i() {
        compare_infos_16::<_, riscv_isa::Compressed>(riscv_isa::Target::rv64i_full());
    }

    compare_test!(
        rv32i,
        riscv_isa::Instruction,
        riscv_isa::Target::rv32i_full()
    );

    compare_test!(
        rv64i,
        riscv_isa::Instruction,
        riscv_isa::Target::rv64i_full()
    );
}

/// Compare [`Info`] outputs for a range of decoded insns against a reference
#[allow(dead_code)]
fn compare_infos_16<D, I>(base: D)
where
    D: Decode<I> + Clone,
    I: Info + core::fmt::Debug,
    I::Register: From<<Kind as Info>::Register> + core::fmt::Debug,
    base::Set: From<D>,
{
    let ours = base::Set::from(base.clone());
    (0..0x3fff)
        .flat_map(|h| {
            let high = h << 2;
            [0b00, 0b01, 0b10].map(|l| l | high)
        })
        .for_each(|i| compare_infos(ours.decode_16(i), base.decode_16(i), i))
}

/// Compare [`Info`] outputs for a range of decoded insns against a reference
#[allow(dead_code)]
fn compare_infos_32<D, I>(base: D, num: u32, ex: u8)
where
    D: Decode<I> + Clone,
    I: Info + core::fmt::Debug,
    I::Register: From<<Kind as Info>::Register> + core::fmt::Debug,
    base::Set: From<D>,
{
    let ours = base::Set::from(base.clone());
    let ex = ex - 2;
    ((num << ex)..((num + 1) << ex))
        .map(|i| i << 2 | 0b11)
        .filter(|i| i & 0b11100 != 0b11100)
        .for_each(|i| compare_infos(ours.decode_32(i), base.decode_32(i), i))
}

/// Compare the [`Info`] outputs of `Option<Kind>` to another [`Info`]
fn compare_infos<I>(kind: Option<Kind>, other: I, insn: impl core::fmt::LowerHex)
where
    I: Info + core::fmt::Debug,
    I::Register: From<<Kind as Info>::Register> + core::fmt::Debug,
{
    assert_eq!(
        kind.branch_target(),
        other.branch_target(),
        "Branch targets differ for {insn:0x} ({kind:?} vs. {other:?})"
    );
    assert_eq!(
        kind.inferable_jump_target(),
        other.inferable_jump_target(),
        "Inferable jump targets differ for {insn:0x} ({kind:?} vs. {other:?})"
    );
    assert_eq!(
        kind.uninferable_jump_target().map(|(r, i)| (r.into(), i)),
        other.uninferable_jump_target(),
        "Inferable jump targets differ for {insn:0x} ({kind:?} vs. {other:?})"
    );
    assert_eq!(
        kind.upper_immediate(0).map(|(r, i)| (r.into(), i)),
        other.upper_immediate(0),
        "Upper immediates at 0 differ for {insn:0x} ({kind:?} vs. {other:?})"
    );
    assert_eq!(
        kind.upper_immediate(0x8000).map(|(r, i)| (r.into(), i)),
        other.upper_immediate(0x8000),
        "Upper immediates at 0x8000 differ for {insn:0x} ({kind:?} vs. {other:?})"
    );
    assert_eq!(
        kind.is_return_from_trap(),
        other.is_return_from_trap(),
        "Disaggreement on return from trap for {insn:0x} ({kind:?} vs. {other:?})"
    );
    assert_eq!(
        kind.is_ecall_or_ebreak(),
        other.is_ecall_or_ebreak(),
        "Disaggreement on return from trap for {insn:0x} ({kind:?} vs. {other:?})"
    );
    assert_eq!(
        kind.is_call(),
        other.is_call(),
        "Disaggreement on return from trap for {insn:0x} ({kind:?} vs. {other:?})"
    );
    assert_eq!(
        kind.is_return(),
        other.is_return(),
        "Disaggreement on return from trap for {insn:0x} ({kind:?} vs. {other:?})"
    );
}
