use crate::decoder::{Decode, Decoder};

#[derive(Debug, Eq, PartialEq)]
pub struct Header {
    pub payload_len: u8,
    pub trace_type: TraceType,
    pub has_timestamp: bool,
    pub cpu_index: u8,
}

impl Decode for Header {
    fn decode(decoder: &mut Decoder) -> Self {
        let payload_length = decoder.read_fast_u32(5);
        let trace_type = TraceType::decode(decoder);
        let has_timestamp = decoder.read_bool_bit();
        let cpu_index = decoder.read_fast_u32(decoder.conf.cpu_index_width);
        Header {
            payload_len: payload_length.try_into().unwrap(),
            trace_type,
            has_timestamp,
            cpu_index: cpu_index.try_into().unwrap(),
        }
    }
}


#[derive(Debug, Eq, PartialEq)]
pub enum TraceType {
    Instruction,
}

impl Decode for TraceType {
    fn decode(decoder: &mut Decoder) -> Self {
        match decoder.read_fast_u32(2) {
            0b10 => TraceType::Instruction,
            unknown => panic!("Unknown trace type: {:?}", unknown),
        }
    }
}
