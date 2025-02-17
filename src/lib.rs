// Copyright (C) 2024 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

//! # Rust implementation of Efficient Trace for RISC-V's instruction decoder and tracing algorithm
//!
//! This project implements the instruction packet decoder and instruction tracing algorithm for
//! [Efficient Trace for RISC-V](https://github.com/riscv-non-isa/riscv-trace-spec/).
//! This crate is not concerned how the encoder signals a new packet or how the packet is
//! transported to the decoder.
//!
//! See [decoder] for the implementation of the packet decoder and [tracer] for the tracing
//! algorithm.
//!
//! # ETrace features
//! - delta/full address mode
//! - configurable bit width of packet fields
//! - sign based decompression
//! - optional context for instructions
//! - optional timestamp in header
//! - optional implicit return mode
//!
//! Each feature is configurable independently of each other.
//!
//! # no_std
//! This crate is not dependent on the standard library and only uses the Core Library. It can therefore even
//! be used in bare metal environments.
//!
//! # Example
//! ```
//! extern crate riscv_etrace;
//!
//! use riscv_etrace::{ProtocolConfiguration};
//! use riscv_etrace::decoder::{Decoder, DecoderConfiguration};
//! use riscv_etrace::Instruction;
//! use riscv_etrace::Segment;
//! use riscv_etrace::tracer::{ReportTrace, TraceConfiguration, Tracer};
//!
//! // Create your segments from your ELF files.
//! let mut segments: Vec<Segment> = Vec::new();
//!
//! // Use the default protocol level configuration which will define the bit lengths of packet fields.
//! let mut proto_conf = ProtocolConfiguration::default();
//! // But we overwrite the hart index width and assume a maximum of 2^10 harts.
//! proto_conf.cpu_index_width = 10;
//!
//! // Create the decoder configuration.
//! let decoder_conf = DecoderConfiguration {
//!     // We assume that the packets are sign based compressed.
//!     decompress: true,
//! };
//!
//! // A single tracing configuration will be used for the tracer. This may be shared between
//! // multiple tracers for different harts.
//! let trace_conf = TraceConfiguration {
//!     // Pass your parsed ELF segments.
//!     segments: &segments,
//!     // We will use differential addresses for better efficiency.
//!     full_address: false,
//! };
//!
//! struct ExampleReport {
//!     // Here you can define counters etc. which depend on the tracing output.
//! }
//!
//! // Define your custom callbacks such as report_pc:
//! impl ReportTrace for ExampleReport {
//!     fn report_pc(&mut self, pc: u64) {
//!         println!("pc: 0x{:x}", pc);
//!     }
//!
//!     fn report_epc(&mut self, epc: u64) {
//!         println!("epc: 0x{:x}", epc);
//!     }
//!
//!     fn report_instr(&mut self, pc: u64, instr: &Instruction) {
//!         println!("instr: {} {:?}", pc, instr)
//!     }
//!
//!     fn report_branch(&mut self, branches: u8, branch_map: u32, taken: bool) {
//!         println!("branch: {:?} {:032b} {}", branches, branch_map, taken)
//!     }
//! }
//!
//! let mut reporter = ExampleReport {};
//!
//! // Create the packet decoder.
//! let mut decoder = Decoder::new(proto_conf, decoder_conf);
//!
//! // Create each tracer for the hart we want to trace.
//! let mut tracer: Tracer = Tracer::new(
//!     proto_conf,
//!     trace_conf,
//!     &mut reporter,
//! );
//!
//! # let packet_vec: Vec<u8> = vec![0b0101_0000; 32];
//! # let packet_slice = packet_vec.as_slice();
//! # const HART_WE_WANT_TO_TRACE: usize = 0;
//! // Assuming we have a slice given with a packet already written in binary in it,
//! // the decoder will decompress and parse it.
//! // Note that a single decoder can be used for different harts.
//! let packet = decoder.decode_packet(packet_slice).unwrap();
//! println!("{:?}", packet);
//! // Select the packet based on the hart index...
//! if packet.header.hart_index == HART_WE_WANT_TO_TRACE {
//!     // ...and trace it. This will call the previously defined `report...` callbacks.
//!     tracer.process_te_inst(&packet.payload).unwrap();
//! }
//! ```
#![no_std]

pub mod decoder;
pub mod instruction;
pub mod tracer;

pub use instruction::{Instruction, InstructionSize, Name, Segment};

/// Defines the bit widths of the protocols packet fields. Used by the [decoder] and [tracer].
#[derive(Copy, Clone)]
pub struct ProtocolConfiguration {
    pub context_width_p: u8,
    pub time_width_p: u8,
    pub ecause_width_p: u8,
    pub iaddress_lsb_p: u8,
    pub iaddress_width_p: u8,
    pub cache_size_p: u8,
    pub privilege_width_p: u8,
    pub cpu_index_width: u8,
    pub encoder_mode_n: u8,
    pub ioptions_n: u8,
    #[cfg(feature = "implicit_return")]
    pub sijump_p: bool,
    #[cfg(feature = "implicit_return")]
    pub call_counter_size_p: u8,
    #[cfg(feature = "implicit_return")]
    pub return_stack_size_p: u8,
}

impl Default for ProtocolConfiguration {
    fn default() -> Self {
        ProtocolConfiguration {
            context_width_p: 0,
            time_width_p: 0,
            ecause_width_p: 6,
            iaddress_lsb_p: 1,
            iaddress_width_p: 64,
            cache_size_p: 0,
            privilege_width_p: 2,
            cpu_index_width: 2,
            encoder_mode_n: 1,
            ioptions_n: 5,
            #[cfg(feature = "implicit_return")]
            sijump_p: true,
            #[cfg(feature = "implicit_return")]
            call_counter_size_p: 2,
            #[cfg(feature = "implicit_return")]
            return_stack_size_p: 32,
        }
    }
}

