# Rust implementation of Efficient Trace for RISC-V’s instruction decoder and tracing algorithm

This library implements the instruction packet decoder and instruction tracing algorithm for
[Efficient Trace for RISC-V](https://github.com/riscv-non-isa/riscv-trace-spec/).
This crate is not concerned how the encoder signals a new packet or how the packet is  transported to the decoder.



## Testing
Run ``cargo test``.