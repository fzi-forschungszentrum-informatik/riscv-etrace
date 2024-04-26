use crate::decoder::format::{Ext, Format, Sync};
use crate::decoder::header::*;
use crate::decoder::payload::*;
use crate::decoder::DecodeError::ReadTooLong;
use crate::{DecoderConfiguration, DEFAULT_DECODER_CONFIG, DEFAULT_PROTOCOL_CONFIG, ProtocolConfiguration};
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

pub struct Decoder<const PACKET_BUFFER_LEN: usize> {
    packet_data: Option<[u8; PACKET_BUFFER_LEN]>,
    bit_pos: usize,
    proto_conf: ProtocolConfiguration,
    decoder_conf: DecoderConfiguration,
}

// TODO TraceConfiguration checking
// 0 <addr width < 65
// cpu index < 2^5
// CPU_COUNT <= 2^cpu_index_width

pub const DEFAULT_PACKET_BUFFER_LEN: usize = 32;

impl Decoder<DEFAULT_PACKET_BUFFER_LEN> {
    pub fn default() -> Self {
        Decoder::new(DEFAULT_PROTOCOL_CONFIG, DEFAULT_DECODER_CONFIG)
    }
    
    pub fn default_buffer_len(proto_conf: ProtocolConfiguration, decoder_conf: DecoderConfiguration) -> Self {
        Decoder::new(proto_conf, decoder_conf)
    }
}

#[derive(Debug)]
pub enum DecodeError {
    UnknownTraceType(u64),
    BadBranchFmt,
    ReadTooLong {
        bit_pos: usize,
        bit_count: usize,
        buffer_size: usize,
    },
}

impl<const PACKET_BUFFER_LEN: usize> Decoder<PACKET_BUFFER_LEN> {
    pub fn new(proto_conf: ProtocolConfiguration, decoder_conf: DecoderConfiguration) -> Self {
        Decoder {
            packet_data: None,
            bit_pos: 0,
            proto_conf,
            decoder_conf,
        }
    }

    // TODO make private
    pub fn set_buffer(&mut self, array: [u8; PACKET_BUFFER_LEN]) {
        self.bit_pos = 0;
        self.packet_data = Some(array);
    }

    fn read_bit(&mut self) -> Result<bool, DecodeError> {
        if self.bit_pos >= PACKET_BUFFER_LEN * 8 {
            return Err(ReadTooLong {
                buffer_size: PACKET_BUFFER_LEN * 8,
                bit_count: 1,
                bit_pos: self.bit_pos,
            });
        }
        let byte_pos = self.bit_pos / 8;
        let mut value = self.packet_data.unwrap()[byte_pos];
        value >>= self.bit_pos % 8;
        self.bit_pos += 1;
        Ok((value & 1u8) == 0x01)
    }

    fn read(&mut self, bit_count: usize) -> Result<u64, DecodeError> {
        if bit_count == 0 {
            return Ok(0);
        }
        assert!(bit_count <= 64);
        if bit_count + self.bit_pos - 1 >= PACKET_BUFFER_LEN * 8 {
            return Err(ReadTooLong {
                buffer_size: PACKET_BUFFER_LEN * 8,
                bit_count,
                bit_pos: self.bit_pos,
            });
        }
        let byte_pos = self.bit_pos / 8;
        let mut value = u64::from_le_bytes(
            self.packet_data.unwrap()[byte_pos..byte_pos + 8]
                .try_into()
                .unwrap(),
        );
        // Ignore first 'self.bit_pos' LSBs in first byte as they are already consumed.
        value >>= self.bit_pos % 8;
        // Zero out everything except 'bit_count' LSBs if bit_count != 64.
        if bit_count < 64 {
            value &= (1u64 << bit_count) - 1;
        }
        self.bit_pos += bit_count;
        // Check if we need to read into the 9th byte because of an unaligned read
        if self.bit_pos > ((byte_pos + 8) * 8) {
            let missing_bit_count = (self.bit_pos - ((byte_pos + 8) * 8)) % 8;
            // Take 9th byte and mask MSBs that are not read
            let missing_msbs =
                self.packet_data.unwrap()[byte_pos + 8] & u8::MAX >> 8 - missing_bit_count;
            let msbs_u64 = (missing_msbs as u64) << bit_count - missing_bit_count;
            // Shift MSBs into correct position in u64 and add with previously read value
            Ok(value + msbs_u64)
        } else {
            Ok(value)
        }
    }

    // Many times values are read with a size <= 32 bits
    // Reading 32 bits over byte boundary will not work if read is not aligned
    /*fn read_fast(&mut self, bit_count: usize) -> Result<u32, DecodeError> {
        if bit_count == 0 {
            return Ok(0);
        }
        assert!(bit_count <= 32);
        if self.bit_pos + bit_count - 1 >= PACKET_BUFFER_LEN * 8 {
            return Err(ReadTooLong {
                bit_pos: self.bit_pos,
                bit_count,
                buffer_size: PACKET_BUFFER_LEN * 8,
            });
        }
        let byte_pos = self.bit_pos / 8;
        let mut value = u32::from_le_bytes(
            self.packet_data.unwrap()[byte_pos..byte_pos + 4]
                .try_into()
                .unwrap(),
        );
        value >>= self.bit_pos % 8;
        self.bit_pos += bit_count;
        Ok(value & ((1u32 << bit_count) - 1))
    }*/

    pub fn decode_header(&mut self) -> Result<Header, DecodeError> {
        let header = Header::decode(self)?;
        assert_eq!(header.trace_type, TraceType::Instruction);
        // Set the bit position for payload decoding if not at the first bit of the first payload byte
        if self.bit_pos % 8 != 0 {
            self.bit_pos += 8 - (self.bit_pos % 8);
        }
        Ok(header)
    }

    pub fn decode(&mut self, slice: [u8; PACKET_BUFFER_LEN]) -> Result<Packet, DecodeError> {
        self.set_buffer(slice);
        let header = self.decode_header()?;
        if self.decoder_conf.decompress {
            // TODO decompression
            todo!("decompression");
        }
        let format = Format::decode(self)?;

        let payload = match format {
            Format::Ext(Ext::BranchCount) => {
                Payload::Extension(Extension::BranchCount(BranchCount::decode(self)?))
            }
            Format::Ext(Ext::JumpTargetIndex) => {
                Payload::Extension(Extension::JumpTargetIndex(JumpTargetIndex::decode(self)?))
            }
            Format::Branch => Payload::Branch(Branch::decode(self)?),
            Format::Addr => Payload::Address(Address::decode(self)?),
            Format::Sync(Sync::Start) => {
                Payload::Synchronization(Synchronization::Start(Start::decode(self)?))
            }
            Format::Sync(Sync::Trap) => {
                Payload::Synchronization(Synchronization::Trap(Trap::decode(self)?))
            }
            Format::Sync(Sync::Context) => {
                Payload::Synchronization(Synchronization::Context(Context::decode(self)?))
            }
            Format::Sync(Sync::Support) => {
                Payload::Synchronization(Synchronization::Support(Support::decode(self)?))
            }
        };
        Ok(Packet { header, payload })
    }

    pub fn bit_pos(&self) -> usize {
        self.bit_pos
    }
}

trait Decode<const PACKET_BUFFER_LEN: usize> {
    fn decode(decoder: &mut Decoder<PACKET_BUFFER_LEN>) -> Result<Self, DecodeError>
    where
        Self: Sized;
}

#[derive(Debug)]
pub struct Packet {
    pub header: Header,
    pub payload: Payload,
}

#[cfg(test)]
mod tests {
    use crate::decoder::*;

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
        decoder.set_buffer(buffer);
        // testing for bit position
        assert_eq!(decoder.read(6).unwrap(), 0b011111);
        assert_eq!(decoder.bit_pos, 6);
        assert_eq!(decoder.read(2).unwrap(), 0b01);
        assert_eq!(decoder.bit_pos, 8);
        assert_eq!(decoder.read(6).unwrap(), 0b011111);
        assert_eq!(decoder.bit_pos, 14);
        // read over byte boundary
        assert_eq!(decoder.read(10).unwrap(), 0b1001001001);
        assert_eq!(decoder.bit_pos, 24);
        assert_eq!(decoder.read(62).unwrap(), 0x3FFF_F0F0_F0F0_F0F1);
        assert_eq!(decoder.bit_pos, 86);
        assert_eq!(decoder.read(64).unwrap(), 0xC000_0000_0000_0005);
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
        decoder.set_buffer(buffer);
        assert_eq!(decoder.read(1).unwrap(), 0);
        assert_eq!(decoder.read(64).unwrap() as i64, -24);
    }

    #[test_case]
    fn read_entire_buffer() {
        let buffer = [255; DEFAULT_PACKET_BUFFER_LEN];
        let mut decoder = Decoder::default();
        decoder.set_buffer(buffer);
        assert_eq!(decoder.read(64).unwrap(), u64::MAX);
        assert_eq!(decoder.read(64).unwrap(), u64::MAX);
        assert_eq!(decoder.read(64).unwrap(), u64::MAX);
        assert_eq!(decoder.read(64).unwrap(), u64::MAX);
    }

    /*#[test_case]
    fn read_u32() {
        let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
        buffer[0] = 0b1100_0101;
        buffer[1] = 0b1111_1111;
        let mut decoder = Decoder::default(DEFAULT_CONFIGURATION);
        decoder.set_buffer(buffer);
        assert_eq!(decoder.read_fast(2).unwrap(), 0b01);
        assert_eq!(decoder.bit_pos, 2);
        assert_eq!(decoder.read_fast(2).unwrap(), 0b01);
        assert_eq!(decoder.bit_pos, 4);
        assert_eq!(decoder.read_fast(2).unwrap(), 0b00);
        assert_eq!(decoder.bit_pos, 6);
        assert_eq!(decoder.read_fast(1).unwrap(), 0b1);
        assert_eq!(decoder.bit_pos, 7);
        assert_eq!(decoder.read_fast(8).unwrap(), 255);
        assert_eq!(decoder.bit_pos, 15)
    }*/

    #[test_case]
    fn read_bool_bits() {
        let buffer = [0b0101_0101; DEFAULT_PACKET_BUFFER_LEN];
        let mut decoder = Decoder::default();
        decoder.set_buffer(buffer);
        assert_eq!(decoder.read_bit().unwrap(), true);
        assert_eq!(decoder.read_bit().unwrap(), false);
        assert_eq!(decoder.read_bit().unwrap(), true);
        assert_eq!(decoder.read_bit().unwrap(), false);
        assert_eq!(decoder.read_bit().unwrap(), true);
        assert_eq!(decoder.read_bit().unwrap(), false);
        assert_eq!(decoder.read_bit().unwrap(), true);
        assert_eq!(decoder.read_bit().unwrap(), false);
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
        decoder.set_buffer(buffer);
        assert_eq!(decoder.read(6).unwrap(), 0);
        // Modelled after read_address call with iaddress_width_p: 64 and iaddress_lsb_p: 1
        assert_eq!((decoder.read(63).unwrap() << 1), -248i64 as u64);
    }
}
