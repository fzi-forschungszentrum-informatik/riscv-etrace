//! # Rust implementation of Efficient Trace for RISC-V's instruction decoder and tracing algorithm
//!
//! This project implements the instruction packet decoder and instruction tracing algorithm for
//! [Efficient Trace for RISC-V (Version 1.1.3)](https://github.com/riscv-non-isa/riscv-trace-spec/).
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
//! - (only decoding) optional context for instructions
//! - (only decoding) optional timestamp in header
//! - (only decoding) optional implicit return mode
//!
//! Each feature is configurable independently of each other.
//!
//! # no_std
//! This crate is not dependent on the standard library and only uses libcore. It can therefor even
//! be used in bare metal environments.
//!
//! # Example
//! ```
//! extern crate riscv_etrace;
//!
//! use riscv_etrace::{DEFAULT_PROTOCOL_CONFIG, ProtocolConfiguration};
//! use riscv_etrace::decoder::{Decoder, DecoderConfiguration};
//! use riscv_etrace::Instruction;
//! use riscv_etrace::Segment;
//! use riscv_etrace::tracer::{TraceConfiguration, Tracer};
//!
//! // Create your segments from your ELF files.
//! let mut segments: Vec<Segment> = Vec::new();
//!
//! // Create the protocol level configuration which will define the bit lengths of packet fields.
//! let proto_conf = ProtocolConfiguration {
//!     // In this example we assume a maximum of 2^10 of harts...
//!     cpu_index_width: 10,
//!     // ...but everything else will be default.
//!     ..DEFAULT_PROTOCOL_CONFIG
//! };
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
//! // Define your report callbacks such as report_pc:
//! let mut report_pc = |pc| println!("pc: 0x{:x}", pc);
//! let mut report_epc = |epc| println!("epc: 0x{:x}", epc);
//! let mut report_instr = |pc: u64, instr: Instruction| { println!("instr: {} {:?}", pc, instr) };
//! let mut report_branch = |branches: u8, branch_map: u32, local_taken: bool|
//!     { println!("branch: {:?} {:032b} {}", branches, branch_map, local_taken) };
//!
//! // Create the packet decoder.
//! let mut decoder = Decoder::new(proto_conf, decoder_conf);
//!
//! // Create each tracer for the hart we want to trace.
//! let mut tracer = Tracer::new(
//!     proto_conf,
//!     trace_conf,
//!     &mut report_pc,
//!     &mut report_epc,
//!     &mut report_instr,
//!     &mut report_branch
//! );
//!
//!
//! # let packet_vec: Vec<u8> = vec![0b0101_0000; 32];
//! # let packet_slice = packet_vec.as_slice();
//! # const HART_WE_WANT_TO_TRACE: usize = 0;
//! // Assuming we have a slice given with a packet already written in binary in it,
//! // the decoder will decompress and parse it.
//! // Note that a single decoder can be used for different harts.
//! let (packet, _consumed_bit_count) = decoder.decode(packet_slice).unwrap();
//! println!("{:?}", packet);
//! // Select the packet based on the hart index...
//! if packet.header.hart_index == HART_WE_WANT_TO_TRACE {
//!     // ...and trace it. This will call the previously defined `report...` callbacks.
//!     tracer.process_te_inst(&packet.payload).unwrap();
//! }
//! ```
#![no_std]

pub mod decoder;

mod disassembler;
pub mod tracer;

pub use crate::disassembler::{Instruction, InstructionSize, Name, Segment};

/// Defines the bit widths of the protocols packet fields. Used by the [decoder] and [tracer].
#[derive(Copy, Clone)]
pub struct ProtocolConfiguration {
    #[cfg(feature = "context")]
    pub context_width_p: usize,
    #[cfg(feature = "time")]
    pub time_width_p: usize,
    pub ecause_width_p: usize,
    pub iaddress_lsb_p: usize,
    pub iaddress_width_p: usize,
    pub cache_size_p: usize,
    pub privilege_width_p: usize,
    pub cpu_index_width: usize,
    pub encoder_mode_n: usize,
    pub ioptions_n: usize,
}

pub const DEFAULT_PROTOCOL_CONFIG: ProtocolConfiguration = ProtocolConfiguration {
    #[cfg(feature = "context")]
    context_width_p: 0,
    #[cfg(feature = "time")]
    time_width_p: 0,
    ecause_width_p: 6,
    iaddress_lsb_p: 1,
    iaddress_width_p: 64,
    cache_size_p: 0,
    privilege_width_p: 2,
    cpu_index_width: 2,
    encoder_mode_n: 1,
    ioptions_n: 5,
};
