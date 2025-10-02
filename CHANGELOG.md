# Changelog

All notable changes to this project will be documented in this file. Its format
is based on https://keepachangelog.com/en/1.1.0/.

## Unreleased

### Fixed

- 16bit instructions were previously decoded as `c.lui` regardless of the rd
  (which needs to be neither `0` or `2`) due to an errorneous condition.
- 32bit instructions were previously decoded as `jalr` based solely on the
  opcode. The "funct3"-field, which must be `0` for `jalr`, was not considered.
- Decoding of `c.lui` instructions' immediate was faulty.

## 0.4.0 - 2025-09-10

### Added

- A new submodule `instruction::bits`.
- A new submodule `decoder::error`.
- A new type `decoder::payload::Payload` which represents both instruction and
  data trace payloads. The previous `Payload` was renamed to `Instructiontrace`.
- A fn `tracer::Tracer::process_payload` for processing instances of the (new)
  `decoder::payload::Payload` without the need to extract
  `decoder::payload::InstructionTrace`.
- Fns `decoder::smi::Packet::trace_type`, `raw_trace_type`, `time_tag` and
  `hart` for querying values and `payload` for deferred decoding of the packet's
  `decoder::payload::Payload`.
- `PartialEq` and `Drop` impls for `decoder::smi::Packet`.
- `TryFrom<u8>` and `PartialEq<u8>` impls for `decoder::smi::TraceType`.
- A new module `decoder::encap` providing support for the RISC-V packet
  encapsulation, containing the types `Packet` and `Normal`.
- A fn `decoder::Decoder::decode_encap_packet` for decoding an (ephemeral)
  `decoder::encap::Packet`.
- A fn `decoder::Builder::with_timestamp_width` for setting a new width for
  packet format specific timestamps.
- A fn `decoder::Builder::with_trace_type_width` for setting a new width for
  packet format specific trace type fields.
- A fn `decoder::Decoder::reset` for resetting the `Decoder` with new data.
- `PartialEq` impl for `decoder::unit::Reference`, `ReferenceIOptions`,
  `ReferenceDOptions`, `PULP` and `PulpIOptions`
- A fn `instruction::Kind::upper_immediate` for extracting effective immediates
  of `auipc`, `lui` and `c.lui` instructions.

### Changed

- The type `instruction::Bits` was moved to a new module `instruction::bits`.
- The old `decoder::payload::Payload` was renamed to `InstructionTrace`.
- Made `decoder::smi::Packet` data members private.
- Made `decoder::smi::Packet` ephemeral, bound by lifetimes associated to the
  `decoder::Decoder` it was decoded with.
- Decoding a `decoder::smi::Packet` does no longer unconditionally decode the
  payload (and emit an error if that fails).
- `decoder::Decoder<U>::decode_smi_packet` no longer requires `U` to impl
  `decoder::unit::Unit`.
- The "simple" example is now capable of processing trace data containing
  arbitrary payloads as long as packets for the traced HART only contain
  instruction trace payloads.
- `decoder::Error` was moved to a new submodule `decoder::error` but is still
  availible as `decoder::Error` via a re-export.
- `decoder::smi::TraceType` has one more variant `Data`, indicating a data
  tracing payload.

## 0.3.0 - 2025-08-16

### Added

- `alloc` feature for enabling types, impls and fns that require the `alloc`
  crate.
- Basic support for 48bit and 64bit long instructions.
- The `instruction::base::Set` associated fns `decode_48` and `decode_64`.
- A trait `decoder::unit::DebugIOptions` combining `decoder::unit::IOptions` and
  `Debug`.
- A `decoder::unit::Unit` type `decoder::unit::PULP` for PULP's `rv_tracer`.
- A type `decoder::unit::NoOptions` representing an empty set of options.
- A `binary::Binary` adapter `binary::basic::Segment` for individual raw code
  segments.
- A fn `binary::basic::from_segment` (reexported from `binary`) for convenient
  creation of a `binary::Binary` from raw code segments.
- `decoder::unit::IOptions` impl for `Box<decoder::unit::IOptions>`.
- A type `decoder::unit::Plug` for type erasing `decoder::unit::Unit`s.
- A fn `decoder::unit::Unit::plug` for creating `decoder::unit::Plug`s.
- A fn `decoder::Decoder::unit` for retrieving a `decoder::Decoder`s unit.
- A trait `binary::error::MaybeMissError` combining `binary::error::MaybeMiss`
  and `core::error::Error`, along with a blanket impl for all eligible types.
- `binary::error::MaybeMiss` impl for `Box<binary::error::MaybeMiss>`.
- `binary::error::Miss` impls for `Box<dyn binary::error::MaybeMiss>` and
  `Box<dyn binary::error::MaybeMissError>`.
- `binary::Binary` impl for `Box<binary::Binary>`.
- A `binary::Binary` helper `binary::boxed::BoxedError` which wraps `Error`s
  in dynamically dispatchable `Box`es.
- A type alias `binary::BoxedBinary` for a `Box<dyn Binary>` with a specific,
  fixed `Error` type.
- A provided fn `binary::Binary::boxed` for creation of `binary::BoxedBinary`.
- A `binary::Binary` adapter `binary::basic::SimpleMap` for fixed, small code
  fragments such as bootroms.
- Fns `binary::basic::from_map` and `binary::basic::from_sorted_map` (both
  reexported from `binary`) for creating `binary::basic::SimpleMap`s.
- A `binary::Binary` adapter `binary::basic::Func` for using `FnMut`s.
- A fn `binary::basic::from_fn` (reexported from `binary`) for convenient
  creation of a `binary::Binary` from an `FnMut`.
- A trait `binary::error::Miss` for creation of error values indicating a
  "miss".
- `binary::Binary` impl for `Option` now requires the inner binary's `Error` to
  be `binary::error::Miss` rather than `binary::error::MaybeMiss`.
- `binary::Binary` impl for `binary::Multi` now requires the inner binary's
  `Error` to be `binary::error::Miss` rather than `binary::error::MaybeMiss`.
- A fn `decoder::Decoder::byte_pos` exposing the current position within the
  `decoder::Decoder`'s inner buffer.
- The type `tracer::item::Context` for handling and communicating updates to the
  execution context.
- `types::Privilege` impl for `Hash`.
- `Display` impl for `instruction::Instruction`, `instruction::Kind` and the
  various `instruction::format::Type*`.

### Changed

- Moved reference checking logic out of the "simple" example into the `spike`
  module, removing some potential distraction from the show case.
- The `instruction::Bits` has two more variants `Bit48` and `Bit64`.
- The `instruction::Size` has two more variants `Wide` and `ExtraWide`.
- `(A, B)` now implements `binary::Binary` only if both binaries agree on their
  `binary::Binary::Error` type, and selects `B` only if `A` yield a "miss".
- The `tracer::Tracer` fns `process_te_inst`, `process_sync` and
  `process_support` are now also generic over the pyloads' doptions.
- The "simple" example now has a proper argument parser which enables a wider
  variety of use-cases.
- `decoder::unit::Unit` now requires `IOptions` and `DOptions` to be `'static`.
- `binary::Offset` now requires the inner `binary::Binary`'s `Error` impl
  `binary::error::Miss`.
- `binary::Offset` now does not wrap addresses but reports a "miss" for
  addresses lower than the offset.
- `tracer::Tracer` now communicates updates to the execution context via the
  `tracer::item::Kind::Context` variant.
- Integrated header fields directly into `decoder::smi::Packet`.
- Made `instruction::binary` a toplevel module.
- Moved `MaybeMiss` and `NoInstruction` from `binary` to `binary::error`.
- Moved `binary::Multi` from `binary` to `binary::combinators`. It is, however,
  reexported as `binary::Multi`.
- Moved `binary::Func` `binary::from_fn` and `binary::Empty` from `binary` to
  `binary::basic`. However, `from_fn` and `Empty` are reexported from `binary`.
- Moved `instruction::elf` to `binary`.
- The "simple" example will attempt to filter out context updates occuring on
  resynchronization packets when comparing against a reference spike trace.
- `tracer::item::Item` now has a variant `Context` for communicating updates to
  the execution context.
- When comparing against a reference, the "simple" example now only aborts on
  mismatches of regular items.
- Include (known) disassembled instruction in output of simple example.

### Removed

- `binary::Binary` impl for `&[(u64, Instruction)]`. Users may use the adapter
  `binary::basic::SimpleMap` instead.
- `binary::Binary` impl for `FnMut`. Users may use `binary::Func` instead.
- `binary::error::MaybeMiss::miss`. It's now part of a separate trait
  `binary::error::Miss`.
- `decoder::smi::Packet::header` and `decoder::smi::Header`. Relevant fields are
  now part of `decoder::smi::Packet` itself.
- `decoder::smi::Packet::len`. This information may be retrieved from the
  `decoder::Decoder` if necessary.

### Fixed

- `decoder::Decoder::bytes_left` now accounts for bits that were consumed by
  decoding operations.

## 0.2.0 - 2025-07-16

### Added

- Trait `instruction::binary::MaybeMiss` for identifying and creating errors
  indicating that an `instruction::binary::Binary` does not cover an address.
- Type `istruction::binary::Multi` for combining a slice of items implementing
  `instruction::binary::Binary` into one.
- An `instruction::binary::Binary` impl for `Option<Binary>`.
- `instruction::elf::Elf` fn for querying its `instruction::base::Set`.
- Convenience construction methods for `instruction::Kind`.
- Support for decoding RV64I instructions.
- Support for 64bit ELF files (as RV64I).
- Type `instruction::base::Set` for specifying a base instruction set (e.g.
  RV32I).
- A fn `instruction::Bits::decode` for instruction base set aware decoding
  `Bits` into `Kind`.

### Changed

- Made `ecause` field in `types::trap::Info` an `u16`.
- The "simple" example now automatically loads `pk.riscv` if the ELF file
  provided has a `pk` file extension.
- When comparing against a reference, the "simple" example now only aborts in PC
  mismatches. Other mismatches are only reported to stderr.
- Cleaned up the "simple" example, making its output both more human firendly
  and compact.
- Redefined `tracer::Item`s, which now distinguish between instruction
  retirement and traps.
- Made `tracer::Tracer` yield special `Item`s for traps.
- Adapted final `instruction::Instruction` of bootrom in simple example to
  reflect the bootrom used by reference flow's spike version.
- Make `instruction::Instruction::extract` take an `instruction::base::Set`
  parameter.
- Moved decoding fns `instruction::Kind::decode_16` and `decode_32` to
  `instruction::base::Set`.

### Removed

- `From<instruction::Bits>` impl for `instruction::Instruction`.

### Fixed

- Corrected segment selection in `elf::Elf::get_insn` for addresses at the
  border of two consecutive segments.
- Correct EPC calculation which may have been incorrect under some
  circumstances.
- Read `ecause` field in spike traces as hex values in simple example.

## 0.1.0 - 2025-05-19

### Added

- Initial version of the `riscv-etrace` library, featuring a decoder, tracer
  and specialized instruction database with limited instruction decoding
  functionality.
- A simple example tracer.
