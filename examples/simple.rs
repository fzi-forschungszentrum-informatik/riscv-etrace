// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Simple tracer for single core platforms
//!
//!     Usage: simple ELF-file trace-file [parameter-file] [reference-trace]
//!
//! This program traces a program provided in the form of an ELF file. The trace
//! is supplies as a file consisting of concatenated trace packets. Optionally,
//! parameters may be supplied in the form of a TOML file (such as `params.toml`
//! in this directory). If an assitional reference spike trace is supplied, this
//! program will compare the reconstructed trace against that reference and
//! abort if a mismatch is found.
//!
//! Only a single hart (hart `0`) is traced.
//!
//! By default, the program prints every traced PC as a hex value to stdout. If
//! run with the environment variable `DEBUG` set to `1`, the program prints
//! trace information in a format similar to the debug output of the reference
//! flow's decoder model, allowing for easy comparison (after some filtering).

mod spike;

const TARGET_HART: usize = 0;

fn main() {
    use riscv_etrace::decoder;
    use riscv_etrace::instruction;
    use riscv_etrace::tracer::{self, Tracer};

    use instruction::binary::Binary;

    let debug = std::env::var_os("DEBUG").map(|v| v == "1").unwrap_or(false);
    let mut args = std::env::args_os().skip(1);

    // For tracing, we need the program to trace ...
    let elf_data = std::fs::read(args.next().expect("No ELF file specified"))
        .expect("Could not load ELF file");
    let elf = elf::ElfBytes::<elf::endian::LittleEndian>::minimal_parse(elf_data.as_ref())
        .expect("Coult not parse ELF file");

    // ... and the trace file.
    let trace_data = std::fs::read(args.next().expect("No trace file specified"))
        .expect("Could not load trace file");

    // Often, we also need the encoder parameters
    let params = args
        .next()
        .map(|p| {
            let params = std::fs::read_to_string(p).expect("Could not load parameters");
            toml::from_str(params.as_ref()).expect("Could not parse parameters")
        })
        .unwrap_or_default();
    if debug {
        eprintln!("Parameters: {params:?}");
    }

    // We need to construct a `Binary`. For PIE executables, we simply assume
    // that they are placed at a known offset.
    let elf = instruction::elf::Elf::new(elf).expect("Could not construct binary from ELF file");
    let base_set = elf.base_set();
    let elf = if elf.inner().ehdr.e_type == elf::abi::ET_DYN {
        elf.with_offset(0x8000_0000)
    } else {
        elf.with_offset(0)
    };

    // Given a reference trace, we can check whether our trace is correct.
    let mut reference = args.next().map(|p| {
        let csv = std::fs::File::open(p).expect("Could open reference trace");
        spike::CSVTrace::new(std::io::BufReader::new(csv), base_set)
    });

    // Depending on how we trace, we'll also observe the bootrom. Not having it
    // results in instruction fetch errors while tracing. This is a
    // representation of spike's bootrom.
    let bootrom = vec![
        (0x1000, instruction::Kind::new_auipc(5, 0).into()),
        (0x1004, instruction::UNCOMPRESSED),
        (0x1008, instruction::UNCOMPRESSED),
        (0x100c, instruction::UNCOMPRESSED),
        (0x1010, instruction::Kind::new_jalr(0, 5, 0).into()),
    ];

    // Finally, construct decoder and tracer...
    let mut decoder = decoder::builder()
        .with_params(&params)
        .build(trace_data.as_ref());
    let mut tracer: Tracer<_> = tracer::builder()
        .with_binary((elf, bootrom.as_slice()))
        .with_params(&params)
        .build()
        .expect("Could not set up tracer");

    // ... and get going.
    let mut icount = 0u64;
    let mut pcount = 0u64;
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
        if packet.header.hart_index == TARGET_HART {
            // We process the packet's contents ...
            tracer
                .process_te_inst(&packet.payload)
                .expect("Could not process packet");
            // and then iterate over all the trace items. Those need to be
            // exhaused before feeding the next packet.
            tracer.by_ref().for_each(|i| {
                let item = i.expect("Error while tracing");

                if debug {
                    if let Some(info) = item.trap() {
                        if let Some(tval) = info.tval {
                            println!("  TRAP: ecause: {} tval: 0x{tval:0x}", info.ecause);
                            println!("  EPC: 0x{:0x}", item.pc());
                        } else {
                            println!("  TRAP(interrupt): ecause: {}", info.ecause);
                        }
                    } else {
                        println!("report_pc[{icount}] --------------> 0x{:0x}", item.pc());
                    }
                } else {
                    println!("{:0x}", item.pc());
                }

                if let Some(reference) = reference.as_mut() {
                    assert_eq!(item, reference.next().expect("Reference trace ended"));
                }

                icount += 1;
            });
        }
    }

    if let Some(reference) = reference.as_mut() {
        assert_eq!(reference.next(), None);
    }

    if debug {
        println!("npackets {pcount}");
    }
}

/// Make an iterator over discrete trace items from a reference trace
fn reference_iter(
    reference: impl std::io::Read,
) -> impl Iterator<Item = (u64, u8, u8, u64, u64, u8)> {
    use std::io::BufRead;

    let mut lines = std::io::BufReader::new(reference).lines();
    let header = lines
        .next()
        .expect("No header in reference trace")
        .expect("Could not extract header from reference trace");
    assert_eq!(
        header.trim_end(),
        "VALID,ADDRESS,INSN,PRIVILEGE,EXCEPTION,ECAUSE,TVAL,INTERRUPT"
    );
    lines.filter_map(|l| {
        let line = l.expect("Could not read next reference item");
        let mut fields = line.trim_end().split(',');
        let valid: u8 = fields
            .next()
            .expect("Could not extract \"valid\" field")
            .parse()
            .expect("Could not parse \"valid\" field");
        if valid != 1 {
            return None;
        }

        let address = u64::from_str_radix(
            fields.next().expect("Could not extract \"address\" field"),
            16,
        )
        .expect("Could not parse \"address\" field");
        let _ = fields.next().expect("Could not extract \"insn\" field");
        let privilege: u8 = fields
            .next()
            .expect("Could not extract \"privilege\" field")
            .parse()
            .expect("Could not parse \"privilege\" field");
        let exception: u8 = fields
            .next()
            .expect("Could not extract \"exception\" field")
            .parse()
            .expect("Could not parse \"exception\" field");
        let ecause: u64 = u64::from_str_radix(
            fields.next().expect("Could not extract \"ecause\" field"),
            16,
        )
        .expect("Could not parse \"ecause\" field");
        let tval =
            u64::from_str_radix(fields.next().expect("Could not extract \"tval\" field"), 16)
                .expect("Could not parse \"tval\" field");
        let interrupt: u8 = fields
            .next()
            .expect("Could not extract \"interrupt\" field")
            .parse()
            .expect("Could not parse \"interrupt\" field");
        Some((address, privilege, exception, ecause, tval, interrupt))
    })
}

/// Compare a reference trace item against a generated trace item
fn cmp_reference(
    (address, _, exception, ecause, tval, interrupt): (u64, u8, u8, u64, u64, u8),
    item: &riscv_etrace::tracer::item::Item,
) {
    assert_eq!(item.pc(), address);
    if let Some(trap) = item.trap() {
        assert_eq!(exception, trap.is_exception() as u8);
        assert_eq!(interrupt, trap.is_interrupt() as u8);
        assert_eq!(ecause, trap.ecause);
        if let Some(t) = trap.tval {
            assert_eq!(tval, t);
        }
    } else {
        assert_eq!(exception, 0);
        assert_eq!(interrupt, 0);
    }
}
