//! Implements the packet decoder.
use crate::decoder::format::{Ext, Format, Sync};
use crate::decoder::header::*;
use crate::decoder::payload::*;
use crate::decoder::DecodeError::{ReadTooLong, WrongTraceType};
use crate::{ProtocolConfiguration, DEFAULT_PROTOCOL_CONFIG};
#[cfg(feature = "IR")]
use payload::IRPayload;

mod format;
pub mod header;
pub mod payload;

#[cfg(feature = "time")]
const TIME: u64 = todo!();
#[cfg(feature = "context")]
const CONTEXT: u64 = todo!();
#[cfg(feature = "IR")]
const IR: u64 = todo!();

/// Defines the decoder specific configuration. Used only be the [decoder](self).
#[derive(Copy, Clone)]
pub struct DecoderConfiguration {
    pub decompress: bool,
}

pub const DEFAULT_DECODER_CONFIG: DecoderConfiguration = DecoderConfiguration { decompress: false };

/// A list of possible errors during decoding of a single packet.
#[derive(Debug)]
pub enum DecodeError {
    /// [TraceType] does not indicate an instruction trace. The unknown trace type is returned.
    UnknownTraceType(u64),
    WrongTraceType(TraceType),
    /// The branch format in [BranchCount] is `0b01`.
    BadBranchFmt,
    /// The packet cannot be parsed because the next read of bits would be outside the packet buffer
    /// or too many bits (> 64) were requested.
    ReadTooLong {
        bit_pos: usize,
        bit_count: usize,
        buffer_size: usize,
    },
    DataNotSet
}

/// A decoder for packets. The decoder is stateless in respect to a single packet parse.
/// Multiple packets from different CPUs/Cores/... may be sequentially parsed by a single decoder
/// instance.
pub struct Decoder {
    bit_pos: usize,
    proto_conf: ProtocolConfiguration,
    decoder_conf: DecoderConfiguration,
}

impl Default for Decoder {
    fn default() -> Self {
        Decoder::new(DEFAULT_PROTOCOL_CONFIG, DEFAULT_DECODER_CONFIG)
    }
}

impl Decoder {
    pub fn new(proto_conf: ProtocolConfiguration, decoder_conf: DecoderConfiguration) -> Self {
        Decoder {
            bit_pos: 0,
            proto_conf,
            decoder_conf,
        }
    }

    fn reset(&mut self) {
        self.bit_pos = 0;
    }

    fn read_bit(&mut self, slice: &[u8]) -> Result<bool, DecodeError> {
        if self.bit_pos >= slice.len() * 8 {
            return Err(ReadTooLong {
                buffer_size: slice.len() * 8,
                bit_count: 1,
                bit_pos: self.bit_pos,
            });
        }
        let byte_pos = self.bit_pos / 8;
        let mut value = slice[byte_pos];
        value >>= self.bit_pos % 8;
        self.bit_pos += 1;
        Ok((value & 1_u8) == 0x01)
    }

    fn read(&mut self, bit_count: usize, slice: &[u8]) -> Result<u64, DecodeError> {
        if bit_count == 0 {
            return Ok(0);
        }
        if bit_count > 64 {
            return Err(ReadTooLong {
                buffer_size: slice.len() * 8,
                bit_count,
                bit_pos: self.bit_pos,
            })
        }
        if bit_count + self.bit_pos > slice.len() * 8 {
            return Err(ReadTooLong {
                buffer_size: slice.len() * 8,
                bit_count,
                bit_pos: self.bit_pos,
            });
        }
        let byte_pos = self.bit_pos / 8;
        let mut value = u64::from_le_bytes(
            slice[byte_pos..byte_pos + 8]
                .try_into()
                .unwrap(),
        );
        // Ignore first 'self.bit_pos' LSBs in first byte as they are already consumed.
        value >>= self.bit_pos % 8;
        // Zero out everything except 'bit_count' LSBs if bit_count != 64.
        if bit_count < 64 {
            value &= (1_u64 << bit_count) - 1;
        }
        self.bit_pos += bit_count;
        // Check if we need to read into the 9th byte because of an unaligned read
        if self.bit_pos > ((byte_pos + 8) * 8) {
            let missing_bit_count = (self.bit_pos - ((byte_pos + 8) * 8)) % 8;
            // Take 9th byte and mask MSBs that will not be read
            let missing_msbs =
                slice[byte_pos + 8] & u8::MAX >> (8 - missing_bit_count);
            let msbs_u64 = (missing_msbs as u64) << (bit_count - missing_bit_count);
            // Shift MSBs into correct position in u64 and add with previously read value
            Ok(value + msbs_u64)
        } else {
            Ok(value)
        }
    }

    /// Decodes a single packet consisting of header and payload from a continuous slice of memory.
    /// Returns immediately after parsing one packet. Further bytes are ignored.
    pub fn decode(&mut self, slice: &[u8]) -> Result<Packet, DecodeError> {
        self.reset();

        if self.decoder_conf.decompress {
            // TODO decompression
            todo!("decompression");
        }

        let header = Header::decode(self, slice)?;
        if header.trace_type != TraceType::Instruction {
            return Err(WrongTraceType(header.trace_type))
        }
        // Set the bit position to the beginning of the start of the next byte for payload decoding
        // if not at the first bit of the first payload byte.
        if self.bit_pos % 8 != 0 {
            self.bit_pos += 8 - (self.bit_pos % 8);
        }

        let payload = match Format::decode(self, slice)? {
            Format::Ext(Ext::BranchCount) => {
                Payload::Extension(Extension::BranchCount(BranchCount::decode(self, slice)?))
            }
            Format::Ext(Ext::JumpTargetIndex) => {
                Payload::Extension(Extension::JumpTargetIndex(JumpTargetIndex::decode(self, slice)?))
            }
            Format::Branch => Payload::Branch(Branch::decode(self, slice)?),
            Format::Addr => Payload::Address(AddressInfo::decode(self, slice)?),
            Format::Sync(Sync::Start) => {
                Payload::Synchronization(Synchronization::Start(Start::decode(self, slice)?))
            }
            Format::Sync(Sync::Trap) => {
                Payload::Synchronization(Synchronization::Trap(Trap::decode(self, slice)?))
            }
            Format::Sync(Sync::Context) => {
                Payload::Synchronization(Synchronization::Context(Context::decode(self, slice)?))
            }
            Format::Sync(Sync::Support) => {
                Payload::Synchronization(Synchronization::Support(Support::decode(self, slice)?))
            }
        };
        Ok(Packet { header, payload })
    }

    pub fn bit_pos(&self) -> usize {
        self.bit_pos
    }
}

trait Decode {
    fn decode(decoder: &mut Decoder, slice: &[u8]) -> Result<Self, DecodeError>
    where
        Self: Sized;
}

/// A single protocol packet emitted by the encoder.
/// Each packet consists of a single header and a payload.
#[derive(Debug)]
pub struct Packet {
    pub header: Header,
    pub payload: Payload,
}

#[cfg(test)]
mod tests {
    use crate::decoder::*;

    const DEFAULT_PACKET_BUFFER_LEN: usize = 32;

    #[test_case]
    fn read_u64() {
        let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
        buffer[0] = 0b01_011111;
        buffer[1] = 0b01_011111;
        buffer[2] = 0b10010010;
        buffer[3] = 0xF1;
        buffer[4] = 0xF0;
        buffer[5] = 0xF0;
        buffer[6] = 0xF0;
        buffer[7] = 0xF0;
        buffer[8] = 0xF0;
        buffer[9] = 0xFF;
        buffer[10] = 0b01_111111;
        buffer[11] = 0b1;
        // ...
        buffer[18] = 0b11_110000;
        let mut decoder = Decoder::default();
        decoder.reset();
        // testing for bit position
        assert_eq!(decoder.read(6, &buffer).unwrap(), 0b011111);
        assert_eq!(decoder.bit_pos, 6);
        assert_eq!(decoder.read(2, &buffer).unwrap(), 0b01);
        assert_eq!(decoder.bit_pos, 8);
        assert_eq!(decoder.read(6, &buffer).unwrap(), 0b011111);
        assert_eq!(decoder.bit_pos, 14);
        // read over byte boundary
        assert_eq!(decoder.read(10, &buffer).unwrap(), 0b1001001001);
        assert_eq!(decoder.bit_pos, 24);
        assert_eq!(decoder.read(62, &buffer).unwrap(), 0x3FFF_F0F0_F0F0_F0F1);
        assert_eq!(decoder.bit_pos, 86);
        assert_eq!(decoder.read(64, &buffer).unwrap(), 0xC000_0000_0000_0005);
        assert_eq!(decoder.bit_pos, 150);
    }

    #[test_case]
    fn read_i64() {
        let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
        buffer[0] = 0b1101000_0;
        buffer[1] = 0xFF;
        buffer[2] = 0xFF;
        buffer[3] = 0xFF;
        buffer[4] = 0xFF;
        buffer[5] = 0xFF;
        buffer[6] = 0xFF;
        buffer[7] = 0xFF;
        buffer[8] = 0b1;
        let mut decoder = Decoder::default();
        decoder.reset();
        assert_eq!(decoder.read(1, &buffer).unwrap(), 0);
        assert_eq!(decoder.read(64, &buffer).unwrap() as i64, -24);
    }

    #[test_case]
    fn read_entire_buffer() {
        let buffer = [255; DEFAULT_PACKET_BUFFER_LEN];
        let mut decoder = Decoder::default();
        decoder.reset();
        assert_eq!(decoder.read(64, &buffer).unwrap(), u64::MAX);
        assert_eq!(decoder.read(64, &buffer).unwrap(), u64::MAX);
        assert_eq!(decoder.read(64, &buffer).unwrap(), u64::MAX);
        assert_eq!(decoder.read(64, &buffer).unwrap(), u64::MAX);
    }

    /*#[test_case]
    fn read_u32() {
        let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
        buffer[0] = 0b1100_0101;
        buffer[1] = 0b1111_1111;
        let mut decoder = Decoder::default(DEFAULT_CONFIGURATION);
        decoder.set_buffer(buffer);
        assert_eq!(decoder.read_fast(2, &buffer).unwrap(), 0b01);
        assert_eq!(decoder.bit_pos, 2);
        assert_eq!(decoder.read_fast(2, &buffer).unwrap(), 0b01);
        assert_eq!(decoder.bit_pos, 4);
        assert_eq!(decoder.read_fast(2, &buffer).unwrap(), 0b00);
        assert_eq!(decoder.bit_pos, 6);
        assert_eq!(decoder.read_fast(1, &buffer).unwrap(), 0b1);
        assert_eq!(decoder.bit_pos, 7);
        assert_eq!(decoder.read_fast(8, &buffer).unwrap(), 255);
        assert_eq!(decoder.bit_pos, 15)
    }*/

    #[test_case]
    fn read_bool_bits() {
        let buffer = [0b0101_0101; DEFAULT_PACKET_BUFFER_LEN];
        let mut decoder = Decoder::default();
        decoder.reset();
        assert!(decoder.read_bit(&buffer).unwrap());
        assert!(!decoder.read_bit(&buffer).unwrap());
        assert!(decoder.read_bit(&buffer).unwrap());
        assert!(!decoder.read_bit(&buffer).unwrap());
        assert!(decoder.read_bit(&buffer).unwrap());
        assert!(!decoder.read_bit(&buffer).unwrap());
        assert!(decoder.read_bit(&buffer).unwrap());
        assert!(!decoder.read_bit(&buffer).unwrap());
    }

    #[test_case]
    fn missing_msb_shift_is_correct() {
        let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
        buffer[0] = 0b00_000000;
        buffer[1] = 0xE1;
        buffer[2] = 0xFF;
        buffer[3] = 0xFF;
        buffer[4] = 0xFF;
        buffer[5] = 0xFF;
        buffer[6] = 0xFF;
        buffer[7] = 0xFF;
        buffer[8] = 0b00_111111;
        let mut decoder = Decoder::default();
        decoder.reset();
        assert_eq!(decoder.read(6, &buffer).unwrap(), 0);
        // Modelled after read_address call with iaddress_width_p: 64 and iaddress_lsb_p: 1
        assert_eq!((decoder.read(63, &buffer).unwrap() << 1), -248i64 as u64);
    }
}
