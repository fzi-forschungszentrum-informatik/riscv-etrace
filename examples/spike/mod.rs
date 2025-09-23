// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Spike trace utilities

use std::io::BufRead;

use riscv_etrace::decoder;
use riscv_etrace::instruction;
use riscv_etrace::tracer::item::{self, Item};
use riscv_etrace::types::Privilege;

use decoder::payload::InstructionTrace;
use instruction::base;

/// Reference flow spike CSV trace
///
/// This [`Iterator`] yields trace [`Item`]s based on CSV trace data produced by
/// the reference flow's patched spike ISS.
pub struct CSVTrace<R: BufRead> {
    lines: std::io::Lines<R>,
    base: base::Set,
    intermediate: Option<Item>,
    last_address: u64,
    last_priv: Option<Privilege>,
}

impl<R: BufRead> CSVTrace<R> {
    /// Create a new trace
    ///
    /// Create a new trace from the CSV data provided by the given `reader`.
    /// Instructions will be decoded assuming the given `base`. This fn will
    /// panic if a CSV header could not be extracted or if it does not match the
    /// expected format.
    pub fn new(reader: R, base: base::Set) -> Self {
        let mut lines = reader.lines();
        let header = lines
            .next()
            .expect("No header in reference trace")
            .expect("Could not extract header from reference trace");
        assert_eq!(
            header.trim_end(),
            "VALID,ADDRESS,INSN,PRIVILEGE,EXCEPTION,ECAUSE,TVAL,INTERRUPT"
        );
        Self {
            lines,
            base,
            intermediate: None,
            last_address: 0,
            last_priv: None,
        }
    }
}

impl<R: BufRead> Iterator for CSVTrace<R> {
    type Item = Item;

    fn next(&mut self) -> Option<Self::Item> {
        use instruction::info::Info;
        use instruction::Instruction;
        use riscv_etrace::types::trap;

        if let Some(item) = self.intermediate.take() {
            return Some(item);
        }

        let line = self
            .lines
            .by_ref()
            .map(|l| l.expect("Could not read next reference item"))
            .find(|l| l.starts_with("1,"))?;
        let mut fields = line.trim_end().split(',').skip(1);

        let address = u64::from_str_radix(
            fields.next().expect("Could not extract \"address\" field"),
            16,
        )
        .expect("Could not parse \"address\" field");
        let insn = u32::from_str_radix(
            fields
                .next()
                .expect("Could not extract \"instruction\" field"),
            16,
        )
        .expect("Could not parse \"instruction\" field")
        .to_le_bytes();
        let (insn, _) =
            Instruction::extract(&insn, &self.base).expect("Could not decode instruction");
        let privilege = fields
            .next()
            .expect("Could not extract \"privilege\" field")
            .parse::<u8>()
            .expect("Could not parse \"privilege\" field")
            .try_into()
            .expect("Invalid value for privilege");
        let exception: u8 = fields
            .next()
            .expect("Could not extract \"exception\" field")
            .parse()
            .expect("Could not parse \"exception\" field");
        let ecause: u64 = u64::from_str_radix(
            fields.next().expect("Could not extract \"ecause\" field"),
            16,
        )
        .expect("Could not parse \"ecause\" field")
            & 0x7fffffff;
        let ecause = ecause.try_into().expect("Unexpectedly large ecause value");
        let tval =
            u64::from_str_radix(fields.next().expect("Could not extract \"tval\" field"), 16)
                .expect("Could not parse \"tval\" field");
        let interrupt: u8 = fields
            .next()
            .expect("Could not extract \"interrupt\" field")
            .parse()
            .expect("Could not parse \"interrupt\" field");

        let item = if exception == 0 {
            // Regular execution
            let item = Item::new(address, insn.into());
            if self.last_priv != Some(privilege) {
                self.last_priv = Some(privilege);
                self.intermediate = Some(item);
                let ctx = item::Context {
                    privilege,
                    context: Default::default(),
                };
                Item::new(address, ctx.into())
            } else {
                item
            }
        } else if interrupt != 0 {
            // Interrupt
            self.last_priv = None;
            Item::new(self.last_address, trap::Info { ecause, tval: None }.into())
        } else if insn.is_ecall_or_ebreak() {
            // ECALL or EBREAK
            self.last_priv = None;
            self.intermediate = Some(Item::new(
                address,
                trap::Info {
                    ecause,
                    tval: Some(tval),
                }
                .into(),
            ));
            Item::new(address, insn.into())
        } else {
            // Exception
            self.last_priv = None;
            Item::new(
                address,
                trap::Info {
                    ecause,
                    tval: Some(tval),
                }
                .into(),
            )
        };

        self.last_address = address;
        Some(item)
    }
}

/// Check a regularly traced item against a reference trait
pub fn check_reference(
    reference: &mut std::iter::Peekable<impl Iterator<Item = Item>>,
    item: &Item,
    payload: &InstructionTrace<impl decoder::unit::IOptions, impl std::any::Any>,
    icount: u64,
) {
    use decoder::sync::Synchronization;

    let refitem = reference.peek().expect("Reference trace ended");
    if item != refitem {
        if !matches!(
            payload,
            InstructionTrace::Synchronization(Synchronization::Start(_))
        ) || matches!(refitem.kind(), item::Kind::Context(_))
            || !matches!(item.kind(), item::Kind::Context(_))
        {
            eprintln!("Traced item {icount} differs from reference!");
            eprintln!("  Traced item: {item:?}");
            eprintln!("  Reference:   {refitem:?}");
            assert!(
                !matches!(item.kind(), item::Kind::Regular(_)) || item.pc() == refitem.pc(),
                "Aborting due to differing PCs ({:0x} vs. {:0x})",
                item.pc(),
                refitem.pc()
            );
            reference.next();
        }
    } else {
        reference.next();
    }
}
