// Copyright (C) 2024 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! # Decoder and tracer for RISC-V ETraces
//!
//! This library provides a [decoder] and a [tracer] for the instruction tracing
//! defined in the [Efficient Trace for RISC-V][etrace] specification. Given
//! trace packets previously retrieved from an encoder and the traced program,
//! these allow reconstruction of the execution path.
//!
//! This library also features a limited [instruction] database with decoding
//! functionality. Currently, only decoding of RV32IC instructions is supported.
//! However, tracing is not impacted by other instructions that do not influence
//! the control flow ("control transfer instructions").
//!
//! # Tracing flow
//!
//! Raw trace data needs to be decoded via [`Decoder`][decoder::Decoder]s,
//! which are constructed via a [`decoder::Builder`]. A builder is usually
//! configured for a trace [`Unit`][decoder::unit::Unit] implementation with
//! specific [`config::Parameters`].
//!
//! A decoded packet or [`Payload`][decoder::payload::Payload] needs to be
//! dispatched to the [`Tracer`][tracer::Tracer] for that RISC-V hart. It is the
//! responsibility of the library user to do so.
//!
//! A [`Tracer`][tracer::Tracer] processes packets and generates a series of
//! tracing [`Item`][tracer::item::Item]s. It is constructed via a
//! [`tracer::Builder`], which is configured for the specific program
//! being traced (in the form of a [`Binary`][instruction::binary::Binary]) and
//! the same [`config::Parameters`] that the decoder was configured with.
//!
//! [`Binary`][instruction::binary::Binary] is a trait abstracting access to
//! [`Instruction`][instruction::Instruction]s. This library provides a number
//! of implementations and utilities for constructing one, including limited
//! instruction decoding capabilities.
//!
//! # ETrace options
//!
//! The following [ETrace][etrace] options are supported:
//! * delta/full address mode
//! * sequentially inferred jumps
//! * implicit return
//!
//! # Crate features
//!
//! Some functionality if controlled via crate features:
//! * `elf`: enables the [`instruction::elf`] module providing a
//!   [`Binary`][instruction::binary::Binary] for static ELF files using the
//!   [`elf`] crate
//! * `serde`: enables (de)serialization of configuration via [`serde`]
//!
//! # no_std
//!
//! This crate does not dependent on `std` and is thus suitable for `no_std`
//! environments.
//!
//! # Example
//!
//! The following example demonstrates basic instruction tracing, with default
//! [`config::Parameters`], a custom [`Binary`][instruction::binary::Binary] and
//! tracing packets placed in a single buffer.
//!
//! ```
//! use riscv_etrace::decoder;
//! use riscv_etrace::instruction::{binary, Instruction};
//! use riscv_etrace::tracer::{self, Tracer};
//!
//! # let binary_data = b"\x14\x41\x11\x05\x94\xc1\x91\x05\xe3\xec\xc5\xfe\x82\x80";
//! # let binary_offset = 0x80000028;
//! # let trace_data = b"\x45\x73\x0a\x00\x00\x20\x41\x01";
//! # let hart_to_trace = 0;
//! let binary = |addr: u64| {
//!     addr.checked_sub(binary_offset)
//!         .and_then(|a| binary_data.split_at_checked(a as usize))
//!         .and_then(|(_, d)| Instruction::extract(d))
//!         .map(|(i, _)| i)
//!         .ok_or(binary::NoInstruction)
//! };
//!
//! let parameters = Default::default();
//! let mut decoder = decoder::Builder::new()
//!     .with_params(&parameters)
//!     .build(trace_data);
//! let mut tracer: Tracer<_> = tracer::Builder::new()
//!     .with_binary(binary)
//!     .with_params(&parameters)
//!     .build()
//!     .unwrap();
//!
//! while decoder.bytes_left() > 0 {
//!     let packet = decoder.decode_smi_packet().unwrap();
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
//!
//! [etrace]: <https://github.com/riscv-non-isa/riscv-trace-spec/>
#![no_std]

pub mod config;
pub mod decoder;
pub mod instruction;
pub mod tracer;
pub mod types;
