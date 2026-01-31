# Changelog

All notable changes to this project will be documented in this file. Its format
is based on https://keepachangelog.com/en/1.1.0/.

## 0.8.0 - 2026-01-31

### Added

- Types `types::stack::VecStack` and `types::stack::BoxStack` which impl
  `types::stack::ReturnStack` and are availible with the `alloc` feature.
- Fns `tracer::Tracer::binary` and `tracer::Tracer::binary_mut` for retrieving
  a (mutable) referencec to the `binary::Binary` used.
- A type `binary::boxed::Error` intended as an `Error` type for boxed
  `binary::Binary`s such as `binary::boxed::BoxedError`.
- A new type `packet::ext::BranchKind` used in `packet::ext::BranchCount`.
- `Display` impl for `config::AddressMode`, `types::Privilege`,
  `types::branch::Map`, `types::trap::Info`, `packet::payload::Payload`,
  `packet::payload::InstructionTrace`, `packet::payload::Branch`,
  `packet::payload::AddressInfo`, `packet::sync::Synchronization`,
  `packet::sync::Start`, `packet::sync::Trap`, `packet::sync::Context`,
  `packet::sync::Support`, `packet::sync::EncoderMode`,
  `packet::sync::QualStatus`, `packet::ext::Extenstion`,
  `packet::ext::BranchCount` and `packet::ext::JumpTargetIndex`.
- Fns `binary::Offset::inner`, `binary::boxed::BoxedError::inner` and
  `binary::combinators::Multi::inner` for accessing wrapped `binary::Binary`s.
- A fn `binary::Offset::offset` for retrieving the offset value.
- A provided `instruction::info::MakeDecode` fn for inferring its value from
  `config::Parameters`.

### Changed

- `instruction::info::Info` gained a new fn for producing an "ignored"
  instruction.
- `instruction::Instruction` now impls `Default` for all `info::Info`s, not only
  for `info::Info`s that impl `Default`.
- `tracer::Tracer` no longer requires `info::Info` to impl `Default`.
- `binary::error::MaybeMissError` now depends on `Send` and `Sync`.
- `binary::boxed::BoxedError::Error` is now `binary::boxed::Error`.
- `binary::BoxedBinary` is now `binary::boxed::Binary`.
- `packet::payload::Extension`, `packet::payload::BranchCount` and
  `packet::payload::JumpTargetIndex` were moved to the new submodule
  `packet::ext`.
- `packet::ext::BranchCount` was redefined: former `address` and `branch_fmt`
  are now conveyed via a new data mamber `kind`.
- The simple example now uses `Display` for printing `packet::payload::Payload`
  and `types::trap::Info`.

### Removed

- `packet::payload::BranchFmt` was replaced by `packet::ext::BranchKind`.

## 0.7.0 - 2026-01-24

### Added

- A fn `packet::decoder::Decoder::decode` for decoding items implementing
  `packet::decoder::Decode`.
- A fn `packet::decoder::Decoder::split_off_to` for splitting of a sub-decoder.
- `TryFrom<packet::encap::Packet<packet::decoder::Decoder>>` impl for
  `packet::encap::Packet<packet::payload::Payload>`.
- `TryFrom<packet::encap::Normal<packet::decoder::Decoder>>` impl for
  `packet::encap::Normal<packet::payload::Payload>`.
- `packet::encap::Normal::decode_payload` for `packet::decoder::Decoder` as
  payload.
- `TryFrom<packet::smi::Packet<packet::decoder::Decoder>>` impl for
  `packet::smi::Packet<packet::payload::Payload>`.
- `packet::smi::Normal::decode_payload` for `packet::decoder::Decoder` as
  payload.
- A fn `tracer::Tracer::is_tracing` for determining whether a `tracer::Tracer`
  is in the tracing state.

### Changed

- The trait `packet::decoder::Decode` was made public.
- `packet::decoder::Decoder::decode_encap_packet` now returns a
  `packet::encap::Packet<packet::decoder::Decoder>` and requires the
  `packet::unit::Unit` used to be `Clone`.
- `packet::decoder::Decoder::decode_smi_packet` now returns a
  `packet::smi::Packet<packet::decoder::Decoder>` and requires the
  `packet::unit::Unit` used to be `Clone`.
- The simple example no longer dumps every packet before decoding its payload.

### Removed

- Type `packet::decoder::Scoped`, which was sued for ephemeral packets. We now
  use `packet::decoder::Decoder` directly.

## 0.6.2 - 2026-01-20

### Changed

- The associated fn `packet::decoder::Decoder::remaining_data` was made public.

## 0.6.1 - 2026-01-19

### Changed

- `generator::Drain` does not clear the `ioptions` and `doptions` of the
  underlying `generator::Generator` any more.

### Fixed

- `generator::step::Kind::is_updiscon` now returns `true` for
  `generator::step::Kind::TrapReturn`.

## 0.6.0 - 2025-12-23

### Added

- A fn `tracer::Builder::with_implicit_return` for initially (un)setting the
  initial return option.
- `From<types::Privilege>` impl for `u8`.
- A type `packet::decoder::Scoped` for scoped `packet::decoder::Decoder`s, i.e.
  `Decoder`s that are restricted and reset to the rest of the original buffer if
  the `Scoped` is dropped.
- A submodule `packet::encoder` providing the `Encoder` type and the `Encode`
  trait.
- A fn `packet::Builder::encoder` for building `packet::encoder::Encoder`s.
- `encoder::Encode` impl for `packet::unit::ReferenceIOptions`,
  `packet::unit::ReferenceDOptions`, `packet::unit::PULPIOptions`,
  `packet::unit::NoOptions`, `packet::sync::QualStatus`,
  `packet::sync::Support`, `packet::sync::Context`, `packet::sync::Trap`,
  `packet::sync::Start`, `packet::sync::Synchronization`,
  `packet::payload::BranchFmt`, `packet::payload::AddressInfo`,
  `packet::payload::Branch`, `packet::payload::JumpTargetIndex`,
  `packet::payload::BranchCount`, `packet::payload::Extension`,
  `packet::payload::InstructionTrace`, `packet::encap::Normal`,
  `packet::encap::Packet` and `packet::smi::Packet`.
- A fn `packet::Builder::with_compression` for controlling whether
  `packet::encoder::Encoder` created through the `packet::Builder` compress.
- `From<packet::sync::EncoderMode>` impl for `u8`
- A fn `packet::smi::Packet::payload` for accessing the packet's payload as is.
- `Clone` impl for `packet::smi::Packet`.
- `From<packet::smi::TraceType>` impl for `u8`.
- A fn `packet::encap::Normal::payload` for accessing the packet's payload as
  is.
- `Clone` impls for `packet::encap::Packet` and `packet::encap::Normal`.
- `TryFrom` impls for `packet::encap::Packet` and `packet::encap::Normal`
  allowing conversion from ephemeral (containing a `packet::decoder::Scoped`) to
  concrete packets (that contain a decoded `packet::payload::Payload`).
- `packet::decoder::Decode` impl for concrete packets (containing a decoded
  `packet::payload::Payload`).
- A fn `types::branch::Map::take` for extracting branches into a new
  `branch::Map`.
- A type `config::Features` representing optional feature selection.
- A provided fn `packet::unit::IOptions::update_features` for extracting and/or
  updating a selection of `Features`.
- A fn `tracer::Tracer::features` for retrieving the current selection of
  `Features`.
- A module `generator` for tracing payload generation, with submodules `error`,
  `hart2enc`, `state` and `step`.
- An error type `generator::error::Error`.
- A type `generator::state::State` for basic state being used and maintained
  during payload generation.
- A type `generator::state::PayloadBuilder` for producing specific tracing
  payloads based on state held in a `generator::state::State`.
- A type `generator::state::Reason` for expressing the reason an address needs
  to be reported.
- Types `generator::hart2enc::IType`, `generator::hart2enc::JumpType` and
  `generator::hart2enc::CType` for modelling parts of the hart to encoder
  interface.
- A trait `generator::step::Step` as an interface for data fed to a trace
  encoder.
- A type `generator::step::Kind` representing kinds of `generator::step::Step`s.
- Types `generator::Builder`, `generator::Drain`, `generator::Event` and
  `generator::Generator`.
- A fn `generator::builder` for creating a `generator::Builder`.
- An `encoder` example which allows generating traces from CSVs providing the
  encoder inputs.

### Changed

- Adjust documentation and impls of `intruction::info::Info` fns regarding the
  classification of jumps as calls or returns to be in line with the
  specification.
- A `types::branch::Map` now holds at most 32 branches. This is reflected in a
  changed value for `MAX_BRANCHES` and `raw_map` returning an `u32`.
- The `decoder` module was renamed to `packet`.
- The `packet::Decoder` was moved to a new, dedicated module `packet::decoder`.
- `packet::payload::AddressInfo::address` is now an `i64` which is always
  sign-extended.
- `packet::Builder::build` was renamed to `decoder`.
- `packet::error::Error` now has two new variants `BufferTooSmall` and
  `PayloadTooBig`, which may be emitted during encoding attempts.
- `instruction::Kind` now has variants for the `nop` and `c.nop` instructions.
- `packet::smi::Packet` is now generic over its payload.
- `packet::smi::Packet::payload` was renamed to `decode_payload` and is only
  availible if the payload is a `packet::decoder::Scoped`. `payload` now refers
  to a simple accessor fn.
- `packet::encap::Packet` and `packet::encap::Normal` are now generic over their
  payload.
- `packet::encap::Normal::payload` was renamed to `decode_payload` and is only
  availible if the payload is a `packet::decoder::Scoped`. `payload` now refers
  to a simple accessor fn.
- The `tracer::stack` module was moved to `types`.
- `Iterator::size_hint` is now implemented explicitly (and not as a provided fn)
  for `tracer::Tracer`.
- `tracer::item::Context` was moved to `types`.
- `packet::sync::Context::context` is now a plain `u64` which is decoded as `0`
  if the field is absent.

### Fixed

- `packet::encap::Packet`s were not correctly decoded if the width of the srcID
  field was not a multiple of 8 bits.

## 0.5.2 - 2025-11-03

### Fixed

- Removed likely faulty and superfluous logic for handling version 1 traces. As
  a result, the version setting for `tracer::Tracer` currently has no effect.

## 0.5.1 - 2025-10-20

### Fixed

- We now use `doc_cfg` rather than the deprecated `doc_auto_cfg` when building
  docs on [docs.rs](https://docs.rs).

## 0.5.0 - 2025-10-20

### Added

- `Default` impl for `decoder::sync::EncoderMode`, `decoder::sync::QualStatus`,
  `decoder::sync::Support`, `decoder:: unit::ReferenceIOptions` and
  `decoder:: unit::ReferenceDOptions`.
- `TryFrom<u16>`, `TryFrom<u32>` and `TryFrom<u64>` for
  `instruction::bits::Bits`.
- A fn `instruction::Instruction::decode` for decoding `instruction::bits::Bits`
  into an `instruction::Instruction`.
- An optional dependency on `riscv-isa`.
- `instruction::info::Info` impl for `riscv_isa::Instruction`.
- `instruction::info::Decode<riscv_isa::Instruction>` and
  `instruction::MakeDecode` impl for `riscv_isa::Target`.
- `From<riscv_isa::Target>` impl for `instruction::base::Set`.
- A type `types::branch::Error` for errors emitted by fns associated to
  `types::branch::Map`.
- A constant `types::branch::Map::MAX_BRANCHES` for the maximum number of
  branches a `types::branch::Map` can hold.
- A new submodule `instruction::info` hosting the trait `Info` which provides
  instruction information, `Decode` for decoding an `Info` and `MakeDecode` for
  constructing `Decode` for RV32I and RV64I.
- `instruction::info::Info` impls for `Option`, `instruction::Kind` and
  `instruction::Instruction`.
- `instruction::info::Decode<Option<instruction::Kind>>` impl for
  `instruction::base::Set`.
- A fn `instruction::bits::Bits::size` for retrieving the "bits"' instruction
  size.
- `PartialEq` impl for `binary::basic:Func`, `Segment`, `SimpleMap` and `Empty`.
- `PartialEq` impl for `binary::elf::Error`.

### Changed

- The simple example is now more explicit when aborting due to untraced items
  when run in reference mode.
- The simple example now rejects compressed instructions in reference CSV traces
  if any of the upper bits (that cannot belong to the instruction) are set.
- `binary::elf::Elf` is now generic over its `instruction::info::Decode`,
  requireing `instruction::info::MakeDecode` for directly associated fns.
- `binary::elf::elf::base_set` now returns a reference to its
  `instruction::info::Decode` rather than a `instruction::base::Set` by value.
- The optional `elf` dependency was upgraded to version `0.8`.
- `types::branch::Map::push_branch_taken` and `types::branch::Map::append` now
  report an error on failure to add branches rather than silently ignoring the
  condition.
- `tracer::error::Error` has a new variant `CannotAddBranches` which is used for
  communicating failures to add branches to a `types::branch::Map`.
- `tracer::Tracer`, `tracer::item::Item` and `tracer::item::Kind` are now
  generic over the `instruction::info::Info` included in tracing items.
- Moved constraint of `tracer::Builder`'s type parameter for the `binary::Binary`
  to `tracer::Builder::build`, allowing building `tracer::Tracer`s yielding
  arbitrary `instruction::info::Info`.
- `binary::Binary` is now generic over the `instruction::info::Info` of the
  `instruction::Info` it yields.
- `binary::basic::Func` and `binary::basic::from_fn` are now generic over the
  `instruction::info::Info`.
- `binary::basic::Segment` and `binary::basic::from_segment` can now be
  constructed with arbitrary "bases". The `binary::Binary` impl for `Segment`
  covers all info types for which the base impls `instruction::info::Decode`.
- `binary::basic::SimpleMap`, `binary::basic::from_map` and
  `binary::basic::from_sorted_map` are now generic over the
  `instruction::info::Info`.
- The `binary::Binary` impls of 2-tuples, `Option`, `Box`, `binary::Offset`,
  `binary::basic::Empty`, `binary::combinators::Multi` and `binary::elf::Elf`
  were extended to cover all `instruction::info::Info` given the underlying
  types.
- Lifted constraints on type parameters for `binary::Offset`,
  `binary::combinators::Multi` and `binary::boxed::BoxedError`. This allows for
  creation of those types with a wider rande of paramters, even if they will not
  impl `binary::Binary`.
- `instruciton::Instruction` gained a type parameter for its `info::Info`, which
  was previously fixed to `Option<instruction::Kind>`.
- `instruction::Instruction::extract` now takes a reference to any
  `instruction::info::Decode` as a parameter instread of an
  `instruction::base::Set` value.
- `instruction::Instruction::kind` was renamed to `info`.
- If debug is enabled, the "simple" example now prints number of bytes not
  decoded before each packet on a separate line. The value does now exclude the
  packet's size.
- If debug is enabled, the "simple" example now prints the decoded payload on a
  separate line. In version 0.4.0, we would only print the raw payload as part
  of the packet.

### Removed

- Instruction info query fns `instruciton::Kind::branch_target`,
  `inferable_jump_target`, `uninferable_jump`, `upper_immediate`,
  `is_return_from_trap`, `is_uninferable_discon`, `is_ecall_or_ebreak`,
  `is_call` and `is_return`. The associated functionality is now provided via
  the `instruction::info::Info` impl.
- Instruction decoding fns `instruction::base::Set::decode_16`,
  `instruction::base::Set::decode_32`, `instruction::base::Set::decode_48` and
  `instruction::base::Set::decode_48`. The associated functionality is now
  provided via its `instruction::info::Decode` impl.

### Fixed

- 16bit instructions were previously decoded as `c.lui` regardless of the rd
  (which needs to be neither `0` or `2`) due to an errorneous condition.
- 32bit instructions were previously decoded as `jalr` based solely on the
  opcode. The "funct3"-field, which must be `0` for `jalr`, was not considered.
- Decoding of `c.lui` instructions' immediate was faulty.
- When tracing double traps, we would report an incorrect EPC for the second
  trap.
- We previously did not properly handle some edge-cases concerning reporting of
  an address after an uninferable PC discontinuity.
- Traced PCs are now restrained to the address width provided via encoder
  parameters, resolving an issue with the computation of PCs for sequentially
  inferred jumps.

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
