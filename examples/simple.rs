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

use riscv_etrace::packet;

fn main() {
    use riscv_etrace::binary::{self, Binary};
    use riscv_etrace::instruction;
    use riscv_etrace::tracer::{self, Tracer, item};

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
            clap::arg!(-u --unit <UNIT> "Trace encoder implementation that produced the trace")
                .value_parser(TraceUnitParser),
        )
        .arg(
            clap::arg!(-r --reference <FILE> "Reference spike CSV trace")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            clap::arg!(--"spike-bootrom" "Assume presence of the spike bootrom")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            clap::arg!(--hart <NUM> "Hart to trace")
                .value_parser(clap::value_parser!(u64))
                .default_value("0"),
        )
        .arg(
            clap::arg!(--"hart-index-width" <WIDTH> "Width of the hart index field")
                .value_parser(clap::value_parser!(u8)),
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
            base_set = *elf.base_set();

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
    let unit = matches
        .get_one::<packet::unit::Plug>("unit")
        .cloned()
        .unwrap_or_default();
    let mut decoder = matches
        .get_one("hart-index-width")
        .map(|w| packet::builder().with_hart_index_width(*w))
        .unwrap_or_default()
        .for_unit(unit)
        .with_params(&params)
        .decoder(trace_data.as_ref());
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
        if debug {
            eprintln!("{} bytes left in trace", decoder.bytes_left());
        }
        // We decode a packet ...
        let packet = decoder
            .decode_smi_packet()
            .expect("Could not decode packet");
        pcount += 1;

        // and dispatch it to the tracer tracing the specified hart.
        if packet.hart() == target_hart {
            let payload = packet.decode_payload().expect("Could not decode payload");
            if debug {
                eprintln!("Payload: {payload:?}");
            }
            // We process the packet's contents ...
            tracer
                .process_payload(&payload)
                .expect("Could not process packet");
            // and then iterate over all the trace items. Those need to be
            // exhaused before feeding the next packet.
            tracer.by_ref().for_each(|i| {
                let item = i.expect("Error while tracing");

                let pc = item.pc();
                match item.kind() {
                    item::Kind::Regular(insn) => println!("{pc:0x}\t{insn}"),
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

                if let Some(reference) = reference.as_mut()
                    && let Some(payload) = payload.as_instruction_trace()
                {
                    spike::check_reference(reference, &item, payload, icount);
                }

                icount += 1;
            });
        }
    }

    if let Some(item) = reference.and_then(|mut r| r.next()) {
        panic!("Untraced item in reference: {item:?}");
    }

    eprintln!("Decoded {pcount} packets, traced {icount} items");
}

#[derive(Clone)]
struct TraceUnitParser;

impl clap::builder::TypedValueParser for TraceUnitParser {
    type Value = packet::unit::Plug;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        use clap::error::{ContextKind, ContextValue};

        packet::unit::PLUGS
            .iter()
            .find(|(n, _)| *n == value)
            .map(|(_, p)| p())
            .ok_or_else(|| {
                let mut err =
                    clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd);
                if let Some(arg) = arg {
                    err.insert(
                        ContextKind::InvalidArg,
                        ContextValue::String(arg.to_string()),
                    );
                }
                let value = value
                    .try_into()
                    .map(|s: &str| ContextValue::String(s.into()))
                    .unwrap_or(ContextValue::None);
                err.insert(ContextKind::InvalidValue, value);
                err
            })
    }
}
