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
//! By default, the program prints a single line for every trace item to stdout.
//! If run with the environment variable `DEBUG` set to `1`, the configuration
//! and every packet decoded are printed to stderr.

mod spike;

const TARGET_HART: usize = 0;

fn main() {
    use riscv_etrace::decoder;
    use riscv_etrace::instruction;
    use riscv_etrace::tracer::{self, item, Tracer};

    use instruction::binary::Binary;

    let debug = std::env::var_os("DEBUG").map(|v| v == "1").unwrap_or(false);
    let mut args = std::env::args_os().skip(1);

    // For tracing, we need the program to trace ...
    let mut elf_path: std::path::PathBuf = args.next().expect("No ELF file specified").into();
    let elf_data = std::fs::read(&elf_path).expect("Could not load ELF file");
    let elf = elf::ElfBytes::<elf::endian::LittleEndian>::minimal_parse(elf_data.as_ref())
        .expect("Coult not parse ELF file");

    // ... the proxy kernel for non-bare-metal applications ...
    let pk_data = elf_path.extension().is_some_and(|e| e == "pk").then(|| {
        elf_path.set_file_name("pk.riscv");
        eprintln!(
            "Loading additional proxy kernel '{}' due to 'pk' extension...",
            elf_path.display()
        );
        std::fs::read(&elf_path).expect("Could not load pk")
    });
    let pk = pk_data.as_ref().map(|d| {
        elf::ElfBytes::<elf::endian::LittleEndian>::minimal_parse(d.as_ref())
            .expect("Coult not parse pk ELF file")
    });

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
    let mut elf = if elf.inner().ehdr.e_type == elf::abi::ET_DYN {
        vec![elf.with_offset(0x8000_0000)]
    } else {
        vec![elf.with_offset(0)]
    };

    elf.extend(pk.map(|e| {
        instruction::elf::Elf::new(e)
            .expect("Could not construct binary from ELF file")
            .with_offset(0)
    }));
    let elf = instruction::binary::Multi::from(elf);

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
                    let reference = reference.next().expect("Reference trace ended");
                    if item != reference {
                        eprintln!("Traced item {icount} differs from reference!");
                        eprintln!("  Traced item: {item:?}");
                        eprintln!("  Reference:   {reference:?}");
                        assert!(
                            !matches!(item.kind(), item::Kind::Regular(_))
                                || item.pc() == reference.pc(),
                            "Aborting due to differing PCs ({:0x} vs. {:0x})",
                            item.pc(),
                            reference.pc()
                        );
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
