use crate::decoder::{Decode, DecodeError, Decoder};

#[derive(Debug, Eq, PartialEq)]
pub struct Header {
    /// [Payload](crate::decoder::Payload) length in bytes.
    pub payload_len: u8,
    pub trace_type: TraceType,
    pub has_timestamp: bool,
    pub cpu_index: usize,
}

impl Decode for Header {
    fn decode(decoder: &mut Decoder, slice: &[u8]) -> Result<Self, DecodeError> {
        let payload_length = decoder.read(5, slice)?;
        let trace_type = TraceType::decode(decoder, slice)?;
        let has_timestamp = decoder.read_bit(slice)?;
        let cpu_index = decoder.read(decoder.proto_conf.cpu_index_width, slice)?;
        Ok(Header {
            payload_len: payload_length.try_into().unwrap(),
            trace_type,
            has_timestamp,
            cpu_index: cpu_index.try_into().unwrap(),
        })
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum TraceType {
    Instruction,
}

impl Decode for TraceType {
    fn decode(decoder: &mut Decoder, slice: &[u8]) -> Result<Self, DecodeError> {
        match decoder.read(2, slice)? {
            0b10 => Ok(TraceType::Instruction),
            unknown => Err(DecodeError::UnknownTraceType(unknown)),
        }
    }
}
