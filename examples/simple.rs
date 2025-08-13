// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Simple tracer for single core platforms
//!
//! This program traces a program provided in the form of an ELF file. The trace
//! is supplies as a file consisting of concatenated trace packets. Optionally,
//! parameters may be supplied in the form of a TOML file (such as `params.toml`
//! in this directory). If an assitional reference spike trace is supplied, this
//! program will compare the reconstructed trace against that reference and
//! abort if a mismatch is found.
//!
//! Only a single hart is traced. The program prints a single line for every
//! trace item to stdout. Additional information may be printed to stderr.

mod spike;

use std::path::PathBuf;

fn main() {
    use riscv_etrace::binary::{self, Binary};
    use riscv_etrace::decoder;
    use riscv_etrace::instruction;
    use riscv_etrace::tracer::{self, item, Tracer};

    let matches = clap::Command::new("Simple tracer")
        .arg(
            clap::arg!(<trace> "Path to the trace file").value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            clap::arg!(<elf>... "ELF files containing code being traced")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            clap::arg!(-p --params <FILE> "Trace encoder parameters")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            clap::arg!(-r --reference <FILE> "Reference spike CSV trace")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            clap::arg!(--"spike-bootrom" <FILE> "Assume presence of the spike bootrom")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            clap::arg!(--hart <NUM> "Hart to trace")
                .value_parser(clap::value_parser!(u64))
                .default_value("0"),
        )
        .arg(
            clap::arg!(-d --debug "Enable additional debug output")
                .env("DEBUG")
                .action(clap::ArgAction::SetTrue)
                .value_parser(clap::builder::FalseyValueParser::new()),
        )
        .get_matches();

    let debug = matches.get_flag("debug");

    // For tracing, we need the program to trace ...
    let elf_data: Vec<_> = matches
        .get_many::<PathBuf>("elf")
        .expect("No ELF file specified")
        .map(|p| std::fs::read(p).expect("Could not load ELF file"))
        .collect();
    let mut base_set = instruction::base::Set::Rv32I;
    let mut binary: Vec<_> = elf_data
        .iter()
        .map(|d| {
            let elf = elf::ElfBytes::<elf::endian::LittleEndian>::minimal_parse(d.as_ref())
                .expect("Coult not parse ELF file");
            // We need to construct a `Binary`.
            let elf = binary::elf::Elf::new(elf).expect("Could not construct binary from ELF file");
            base_set = elf.base_set();

            // For PIE executables, we simply assume that they are placed at a known
            // offset. This only works it a single ELF is a PIE executable
            if elf.inner().ehdr.e_type == elf::abi::ET_DYN {
                elf.with_offset(0x8000_0000).boxed()
            } else {
                elf.boxed()
            }
        })
        .collect();

    // ... and the trace file.
    let trace_data = std::fs::read(
        matches
            .get_one::<PathBuf>("trace")
            .expect("No trace file specified"),
    )
    .expect("Could not load trace file");

    // Often, we also need the encoder parameters
    let params = matches
        .get_one::<PathBuf>("params")
        .map(|p| {
            let params = std::fs::read_to_string(p).expect("Could not load parameters");
            toml::from_str(params.as_ref()).expect("Could not parse parameters")
        })
        .unwrap_or_default();
    if debug {
        eprintln!("Parameters: {params:?}");
    }

    // Depending on how we trace, we'll also observe the bootrom. Not having it
    // results in instruction fetch errors while tracing. This is a
    // representation of spike's bootrom.
    if matches.get_flag("spike-bootrom") {
        let bootrom = binary::from_sorted_map([
            (0x1000, instruction::Kind::new_auipc(5, 0).into()),
            (0x1004, instruction::UNCOMPRESSED),
            (0x1008, instruction::UNCOMPRESSED),
            (0x100c, instruction::UNCOMPRESSED),
            (0x1010, instruction::Kind::new_jalr(0, 5, 0).into()),
        ])
        .expect("Bootrom was not sorted by address");
        binary.push(bootrom.boxed());
    }

    // Given a reference trace, we can check whether our trace is correct.
    let mut reference = matches.get_one::<PathBuf>("reference").map(|p| {
        let csv = std::fs::File::open(p).expect("Could open reference trace");
        spike::CSVTrace::new(std::io::BufReader::new(csv), base_set).peekable()
    });

    // Finally, construct decoder and tracer...
    let mut decoder = decoder::builder()
        .with_params(&params)
        .build(trace_data.as_ref());
    let mut tracer: Tracer<_> = tracer::builder()
        .with_binary(binary::Multi::from(binary))
        .with_params(&params)
        .build()
        .expect("Could not set up tracer");

    // ... and get going.
    let mut icount = 0u64;
    let mut pcount = 0u64;
    let target_hart = matches.get_one("hart").cloned().unwrap_or(0);
    while decoder.bytes_left() > 0 {
        // We decode a packet ...
        let packet = decoder
            .decode_smi_packet()
            .expect("Could not decode packet");
        if debug {
            eprintln!(
                "Decoded packet: {packet:?} ({} bytes left)",
                decoder.bytes_left()
            );
        }
        pcount += 1;

        // and dispatch it to the tracer tracing the specified hart.
        if packet.hart == target_hart {
            // We process the packet's contents ...
            tracer
                .process_te_inst(&packet.payload)
                .expect("Could not process packet");
            // and then iterate over all the trace items. Those need to be
            // exhaused before feeding the next packet.
            tracer.by_ref().for_each(|i| {
                let item = i.expect("Error while tracing");

                let pc = item.pc();
                match item.kind() {
                    item::Kind::Regular(insn) => println!("{pc:0x}, {insn}"),
                    item::Kind::Trap(info) => {
                        if let Some(tval) = info.tval {
                            println!(
                                "Exception! epc: 0x{pc:0x}, ecause: {}, tval: 0x{tval:0x}",
                                info.ecause,
                            );
                        } else {
                            println!("Interrupt! ecause: {}", info.ecause);
                        }
                    }
                    item::Kind::Context(ctx) => println!("Context! priv: {:?}", ctx.privilege),
                }

                if let Some(reference) = reference.as_mut() {
                    use decoder::payload::Payload;
                    use decoder::sync::Synchronization;
                    let refitem = reference.peek().expect("Reference trace ended");
                    if &item != refitem {
                        if !matches!(
                            packet.payload,
                            Payload::Synchronization(Synchronization::Start(_))
                        ) || matches!(refitem.kind(), item::Kind::Context(_))
                            || !matches!(item.kind(), item::Kind::Context(_))
                        {
                            eprintln!("Traced item {icount} differs from reference!");
                            eprintln!("  Traced item: {item:?}");
                            eprintln!("  Reference:   {refitem:?}");
                            assert!(
                                !matches!(item.kind(), item::Kind::Regular(_))
                                    || item.pc() == refitem.pc(),
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

                icount += 1;
            });
        }
    }

    if let Some(reference) = reference.as_mut() {
        assert_eq!(reference.next(), None);
    }

    eprintln!("Decoded {pcount} packets, traced {icount} items");
}
