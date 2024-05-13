/// A segment of executable RISC-V code which is also used by the encoder.
/// `vaddr_start` is the same address the encoder uses for instructions in this segment.
/// No instruction in this segment has a larger address than `vaddr_end`.
/// A single continuous slice of `[u8; vaddr_end - vaddr_start]` containing instructions lies at
/// the address `in_mem_start` and is internally used by the disassembler.
#[derive(Copy, Clone, Debug)]
pub struct Segment {
    pub vaddr_start: u64,
    pub vaddr_end: u64,
    pub in_mem_start: u64,
}

impl Segment {
    /// Returns true if `vaddr_start <= addr <= vaddr_end`.
    pub fn contains(&self, addr: u64) -> bool {
        self.vaddr_start <= addr && addr <= self.vaddr_end
    }
}
