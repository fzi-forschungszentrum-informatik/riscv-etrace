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
//!
//! The following example demonstrates basic instruction tracing, with default
//! [`ProtocolConfiguration`], a custom [`Binary`][instruction::binary::Binary]
//! and tracing packets placed in a single buffer.
//!
//! ```
//! use riscv_etrace::decoder::Decoder;
//! use riscv_etrace::instruction::{binary, Instruction};
//! use riscv_etrace::tracer::{self, Tracer};
//!
//! # let binary_data = b"\x14\x41\x11\x05\x94\xc1\x91\x05\xe3\xec\xc5\xfe\x82\x80";
//! # let binary_offset = 0x80000028;
//! # let trace_data = b"\x45\x00\x73\x0a\x00\x00\x20\x41\x00\x01";
//! # let hart_to_trace = 0;
//! let binary = |addr: u64| {
//!     addr.checked_sub(binary_offset)
//!         .and_then(|a| binary_data.split_at_checked(a as usize))
//!         .and_then(|(_, d)| Instruction::extract(d))
//!         .map(|(i, _)| i)
//!         .ok_or(binary::NoInstruction)
//! };
//!
//! let proto_conf = Default::default();
//! let mut decoder = Decoder::new(proto_conf).with_data(trace_data);
//! let mut tracer: Tracer<_> = tracer::Builder::new()
//!     .with_config(proto_conf)
//!     .with_binary(binary)
//!     .build()
//!     .unwrap();
//!
//! while decoder.bytes_left() > 0 {
//!     let packet = decoder.decode_packet().unwrap();
//!     eprintln!("{packet:?}");
//!     if packet.header.hart_index == hart_to_trace {
//!         tracer.process_te_inst(&packet.payload).unwrap();
//!         tracer.by_ref().for_each(|i| {
//!             let item = i.unwrap();
//!             if let Some((epc, info)) = item.trap() {
//!                 println!("Trap! EPC={epc:0x}, interrupt={}", info.is_interrupt());
//!             }
//!             println!("PC: {:0x}", item.pc());
//!         });
//!     }
//! }
//! ```
#![no_std]

pub mod decoder;
pub mod instruction;
pub mod tracer;
pub mod types;

pub use instruction::Instruction;

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
    pub sijump_p: bool,
    pub call_counter_size_p: u8,
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
            sijump_p: false,
            call_counter_size_p: 0,
            return_stack_size_p: 0,
        }
    }
}
