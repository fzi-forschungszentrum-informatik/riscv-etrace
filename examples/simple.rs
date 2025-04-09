// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! Simple tracer for single core platforms
//!
//!     Usage: simple ELF-file trace-file [parameter-file]
//!
//! This program traces a program provided in the form of an ELF file. The trace
//! is supplies as a file consisting of concatenated trace packets. Optionally,
//! parameters may be supplied in the form of a TOML file.
//!
//! Only a single hart (hart `0`) is traced. The program prints every traced PC
//! as a hex value to stdout.

const TARGET_HART: usize = 0;

fn main() {
    use riscv_etrace::decoder;
    use riscv_etrace::instruction;
    use riscv_etrace::tracer::{self, Tracer};

    use instruction::binary::Binary;

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

    // We need to construct a `Binary`. For PIE executables, we simply assume
    // that they are placed at a known offset.
    let elf = instruction::elf::Elf::new(elf).expect("Could not construct binary from ELF file");
    let elf = if elf.inner().ehdr.e_type == elf::abi::ET_DYN {
        elf.with_offset(0x8000_0000)
    } else {
        elf.with_offset(0)
    };

    // Depending on how we trace, we'll also observe the bootrom. Not having it
    // results in instruction fetch errors while tracing. This is a
    // representation of spike's bootrom.
    let bootrom = vec![
        (
            0x1000,
            instruction::Kind::auipc(instruction::format::TypeU { rd: 5, imm: 0 }).into(),
        ),
        (0x1004, instruction::UNCOMPRESSED),
        (0x1008, instruction::UNCOMPRESSED),
        (0x100c, instruction::UNCOMPRESSED),
        (
            0x1010,
            instruction::Kind::c_jr(instruction::format::TypeR {
                rd: 0,
                rs1: 5,
                rs2: 0,
            })
            .into(),
        ),
    ];

    // Finally, construct decoder and tracer...
    let mut decoder = decoder::Builder::new()
        .with_params(&params)
        .build(trace_data.as_ref());
    let mut tracer: Tracer<_> = tracer::Builder::new()
        .with_binary((elf, bootrom.as_slice()))
        .with_params(&params)
        .build()
        .expect("Could not set up tracer");

    // ... and get going.
    while decoder.bytes_left() > 0 {
        // We decode a packet ...
        let packet = decoder.decode_packet().expect("Could not decode packet");

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

                println!("{:0x}", item.pc());
            });
        }
    }
}
