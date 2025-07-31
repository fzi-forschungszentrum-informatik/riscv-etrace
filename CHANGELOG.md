# Changelog

All notable changes to this project will be documented in this file. Its format
is based on https://keepachangelog.com/en/1.1.0/.

## Unreleased

### Added

- `types::Privilege` impl for `Hash`.
- `Display` impl for `instruction::Instruction`, `instruction::Kind` and the
  various `instruction::format::Type*`.

### Changed

- When comparing against a reference, the "simple" example now only aborts on
  mismatches of regular items.
- Include (known) disassembled instruction in output of simple example.

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
