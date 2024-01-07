use crate::decoder::{Decode, Decoder};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct Header {
    pub payload_len: u8,
    pub trace_type: TraceType,
    pub has_timestamp: bool,
    pub cpu_index: usize,
}

impl<const HART_COUNT: usize, const PACKET_BUFFER_LEN: usize> Decode<HART_COUNT, PACKET_BUFFER_LEN>
    for Header
{
    fn decode(decoder: &mut Decoder<HART_COUNT, PACKET_BUFFER_LEN>) -> Self {
        let payload_length = decoder.read_fast(5);
        let trace_type = TraceType::decode(decoder);
        let has_timestamp = decoder.read_bit();
        let cpu_index = decoder.read_fast(decoder.conf.cpu_index_width);
        Header {
            payload_len: payload_length.try_into().unwrap(),
            trace_type,
            has_timestamp,
            cpu_index: cpu_index.try_into().unwrap(),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum TraceType {
    Instruction,
}

impl<const HART_COUNT: usize, const PACKET_BUFFER_LEN: usize> Decode<HART_COUNT, PACKET_BUFFER_LEN>
    for TraceType
{
    fn decode(decoder: &mut Decoder<HART_COUNT, PACKET_BUFFER_LEN>) -> Self {
        match decoder.read_fast(2) {
            0b10 => TraceType::Instruction,
            unknown => panic!("Unknown trace type: {:?}", unknown),
        }
    }
}
