# Decoder and tracer for RISC-V ETraces

This library provides a decoder and a tracer for the instruction tracing
defined in the [Efficient Trace for RISC-V](https://github.com/riscv-non-isa/riscv-trace-spec/)
specification. It provides:
* a decoder for instruction trace packets and the extraction from Siemens
  Messaging Infrastructure (SMI) packets,
* a tracer which processes these packets and generates a sequence of tracing
  items, each corresponding to a single traced instruction,
* a specialized instruction database with limited decoding capabilities and
* various utilities, including types for handling trace encoder parameters.

## License

This library is licensed under the [Apache License 2.0](./LICENSE).

## Acknowledgment

<img src="./doc/BMFTR_sponsored.jpg" alt="drawing" height="150" align="left">

Development of this library was partially funded by the German Federal Ministry
of Research, Technology, and Space (BMFTR) within the project Scale4Edge (grant
number 16ME0126).
