# Changelog

All notable changes to this project will be documented in this file. Its format
is based on https://keepachangelog.com/en/1.1.0/.

## Unreleased

### Fixed

- Corrected segment selection in `elf::Elf::get_insn` for addresses at the
  border of two consecutive segments.
- Correct EPC calculation which may have been incorrect under some
  circumstances.
- 16bit instructions were previously decoded as `c.lui` regardless of the rd
  (which needs to be neither `0` or `2`) due to an errorneous condition.
- 32bit instructions were previously decoded as `jalr` based solely on the
  opcode. The "funct3"-field, which must be `0` for `jalr`, was not considered.
- Decoding of `c.lui` instructions' immediate was faulty.

## 0.1.0 - 2025-05-19

### Added

- Initial version of the `riscv-etrace` library, featuring a decoder, tracer
  and specialized instruction database with limited instruction decoding
  functionality.
- A simple example tracer.
