# Decoder and tracer for RISC-V E-Traces

This library provides a decoder and a tracer for the instruction tracing
defined in the [Efficient Trace for RISC-V](https://github.com/riscv-non-isa/riscv-trace-spec/)
specification. It provides:
* a decoder for instruction trace payloads and the extraction from a few packet
  formats,
* a tracer which processes these packets and generates a sequence of tracing
  items, each corresponding to a single traced instruction,
* a specialized instruction database with limited decoding capabilities,
* support for user-provided and external instruction types and
* various utilities, including types for handling trace encoder parameters.

## Supported packet formats

The following packet formats are supported directly by this library:

* [Unformatted Trace & Diagnostic Data Packet Encapsulation for
  RISC-V](https://github.com/riscv-non-isa/e-trace-encap/) and
* Siemens Messaging Infrastructure.

## Supported external instruction information types

In addition to a built-in type for instruction information, the following
libraries are supported:

* [`riscv-isa`](https://crates.io/crates/riscv-isa).

## Supported trace encoders

Some aspects of support packets are defined by trace encoder implementations.
This library provides an interface for abstracting them and support for the
followng specific encoders (and, of course, compatible units):
* the reference encoder implementation and
* the [PULP rv tracer](https://github.com/pulp-platform/rv_tracer).

## License

This library is licensed under the [Apache License 2.0](./LICENSE).

## Acknowledgment

<img src="./doc/BMFTR_sponsored.jpg" alt="drawing" height="150" align="left">

Development of this library was partially funded by the German Federal Ministry
of Research, Technology, and Space (BMFTR) within the project Scale4Edge (grant
number 16ME0126).
