# Changelog

All notable changes to this project will be documented in this file. Its format
is based on https://keepachangelog.com/en/1.1.0/.

## Unreleased

### Added

- `alloc` feature for enabling types, impls and fns that require the `alloc`
  crate.
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
