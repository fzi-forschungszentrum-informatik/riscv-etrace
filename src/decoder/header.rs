use crate::decoder::{Decode, DecodeError, Decoder};

#[derive(Debug, Eq, PartialEq)]
pub struct Header {
    /// [Payload](crate::decoder::Payload) length in bytes.
    pub payload_len: u8,
    pub trace_type: TraceType,
    pub has_timestamp: bool,
    pub cpu_index: usize,
}

impl<const PACKET_BUFFER_LEN: usize> Decode<PACKET_BUFFER_LEN> for Header {
    fn decode(decoder: &mut Decoder<PACKET_BUFFER_LEN>) -> Result<Self, DecodeError> {
        let payload_length = decoder.read(5)?;
        let trace_type = TraceType::decode(decoder)?;
        let has_timestamp = decoder.read_bit()?;
        let cpu_index = decoder.read(decoder.proto_conf.cpu_index_width)?;
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

impl<const PACKET_BUFFER_LEN: usize> Decode<PACKET_BUFFER_LEN> for TraceType {
    fn decode(decoder: &mut Decoder<PACKET_BUFFER_LEN>) -> Result<Self, DecodeError> {
        match decoder.read(2)? {
            0b10 => Ok(TraceType::Instruction),
            unknown => Err(DecodeError::UnknownTraceType(unknown)),
        }
    }
}
