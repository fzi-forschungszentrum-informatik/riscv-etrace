// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! CSV-driven encoder
//!
//! This program processes encoder input from CSVs in the format produced by the
//! reference flow. The encoder input is supplied as a positional paramter, the
//! output file may be either derived from the input's file name or specified
//! explicitly. Optionally, parameters may be supplied in the form of a TOML
//! file (such as `params.toml` in this directory). If a max sync coutner value
//! is specified via the `--max-sync` option, a resync is triggered after that
//! many CSV lines.

use std::num::NonZeroUsize;
use std::path::PathBuf;

use riscv_etrace::{generator, instruction, types};

fn main() {
    use std::io::BufRead;

    use riscv_etrace::packet;

    let matches = clap::Command::new("Simple tracer")
        .arg(
            clap::arg!(<input> "Path to the encoder input")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            clap::arg!(-o --output <FILE> "Output file").value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            clap::arg!(-p --params <FILE> "Trace encoder parameters")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            clap::arg!(--"hart-index-width" <WIDTH> "Width of the hart index field")
                .value_parser(clap::value_parser!(u8)),
        )
        .arg(
            clap::arg!(--"max-sync" <NUM> "Maximum value for the sync counter")
                .value_parser(clap::value_parser!(NonZeroUsize)),
        )
        .arg(
            clap::arg!(-d --debug "Enable additional debug output")
                .env("DEBUG")
                .action(clap::ArgAction::SetTrue)
                .value_parser(clap::builder::FalseyValueParser::new()),
        )
        .get_matches();

    let debug = matches.get_flag("debug");

    // We get the paths first because we may want to infer the output path
    let input = matches
        .get_one::<PathBuf>("input")
        .expect("No input file specified");
    let output = matches
        .get_one::<PathBuf>("output")
        .cloned()
        .unwrap_or_else(|| input.with_extension("te_inst_raw"));

    // We do need tracing input data that we want to encode...
    let input = std::fs::File::open(input).expect("Could not open input file");
    let mut input = std::io::BufReader::new(input).lines();

    // ...and since it's a CSV with a header, we need to consume it
    let header = input
        .next()
        .expect("No header in input")
        .expect("Could not extract header from input");
    assert_eq!(
        header.trim_end(),
        "itype_0,cause,tval,priv,iaddr_0,context,ctype,iretire_0,ilastsize_0",
    );

    // We may want to emulate a trace unit with certain parameters
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

    // We do need also need to open the file we're writing the trace to
    if debug {
        eprintln!("Opening output file: {}", output.display());
    }
    let output = std::fs::File::create(output).expect("Could not create output file");
    let mut output = std::io::BufWriter::new(output);

    let builder = matches
        .get_one("hart-index-width")
        .map(|w| packet::builder().with_hart_index_width(*w))
        .unwrap_or_default()
        .with_params(&params);
    let mut encode = |payload: packet::payload::InstructionTrace| {
        use std::io::Write;

        if debug {
            eprintln!("Encoding payload: {payload:?}");
        }

        let mut buffer = [0; 40];
        let mut encoder = builder.encoder(buffer.as_mut());
        encoder
            .encode(&packet::smi::Packet::new(0b10, 0, payload))
            .expect("Could not encode packet");
        let uncommitted = encoder.uncommitted();
        output
            .write_all(buffer.split_at(buffer.len() - uncommitted).0)
            .expect("Could not write trace to file");
    };

    let mut generator: generator::Generator<CSVLine> = generator::builder()
        .with_params(&params)
        .build()
        .expect("Could not set up payload generator");

    let packet = generator
        .begin_qualification(Default::default(), Default::default())
        .expect("Could not start qualification");
    encode(packet.into());

    let max_sync = matches.get_one::<NonZeroUsize>("max-sync").cloned();
    let mut sync_counter: usize = 0;
    input
        .map(|l| {
            l.expect("Could not read line")
                .parse::<CSVLine>()
                .expect("Could not parse line")
        })
        .for_each(|s| {
            let sync = Some(sync_counter) == max_sync.map(NonZeroUsize::get);
            if sync {
                sync_counter = 0;
            } else {
                sync_counter += 1;
            }
            generator
                .process_step(s, sync.then_some(generator::Event::ReSync))
                .for_each(|p| encode(p.expect("Could not generate packet")));
        });

    generator
        .end_qualification(true)
        .for_each(|p| encode(p.expect("Could not generate packet")));
}

#[derive(Copy, Clone, Debug)]
struct CSVLine {
    itype: generator::hart2enc::IType,
    cause: u16,
    tval: u64,
    privilege: types::Privilege,
    iaddr: u64,
    context: u64,
    ctype: generator::hart2enc::CType,
    iretire: u8,
    ilastsize: instruction::Size,
}

impl std::str::FromStr for CSVLine {
    type Err = String;

    fn from_str(line: &str) -> Result<Self, Self::Err> {
        let mut fields = line.trim_end().split(',');

        let itype = fields
            .next()
            .and_then(|f| f.parse::<u8>().ok())
            .and_then(|f| f.try_into().ok())
            .ok_or(line)?;

        let cause = fields
            .next()
            .and_then(|f| f.parse::<u64>().ok())
            .map(|f| f & 0x7fffffff)
            .and_then(|f| f.try_into().ok())
            .ok_or(line)?;

        let tval = fields
            .next()
            .and_then(|f| u64::from_str_radix(f, 16).ok())
            .ok_or(line)?;

        let privilege = fields
            .next()
            .and_then(|f| f.parse::<u8>().ok())
            .and_then(|f| f.try_into().ok())
            .ok_or(line)?;

        let iaddr = fields
            .next()
            .and_then(|f| u64::from_str_radix(f, 16).ok())
            .ok_or(line)?;

        let context = fields
            .next()
            .and_then(|f| u64::from_str_radix(f, 16).ok())
            .ok_or(line)?;

        let ctype = fields
            .next()
            .and_then(|f| f.parse::<u8>().ok())
            .and_then(|f| f.try_into().ok())
            .ok_or(line)?;

        let iretire = fields.next().and_then(|f| f.parse().ok()).ok_or(line)?;

        let ilastsize: Option<u8> = fields.next().and_then(|f| f.parse().ok());
        let ilastsize = match ilastsize {
            Some(0) => instruction::Size::Compressed,
            Some(1) => instruction::Size::Normal,
            _ => return Err(line.into()),
        };

        Ok(Self {
            itype,
            cause,
            tval,
            privilege,
            iaddr,
            context,
            ctype,
            iretire,
            ilastsize,
        })
    }
}

impl generator::step::Step for CSVLine {
    fn address(&self) -> u64 {
        self.iaddr
    }

    fn kind(&self) -> generator::step::Kind {
        // Note: the reference flow "cheats" by applying sijump in the post-iss
        // step
        generator::step::Kind::from_hart(
            self.itype,
            self.cause,
            self.tval,
            self.ilastsize,
            self.iretire != 0,
            false,
        )
    }

    fn ctype(&self) -> generator::hart2enc::CType {
        self.ctype
    }

    fn context(&self) -> types::Context {
        types::Context {
            privilege: self.privilege,
            context: self.context,
        }
    }
}
