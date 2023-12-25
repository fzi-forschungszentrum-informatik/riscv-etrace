use crate::decoder::format::{Ext, Format, Sync};
use crate::decoder::header::*;
use crate::decoder::payload::*;
#[cfg(feature = "IR")]
use parts::IRPayload;

mod format;
pub mod header;
pub mod payload;

#[cfg(feature = "time")]
const TIME: u64 = todo!();
#[cfg(feature = "context")]
const CONTEXT: u64 = todo!();
#[cfg(feature = "IR")]
const IR: u64 = todo!();

pub const DEFAULT_CONFIGURATION: DecoderConfiguration = DecoderConfiguration {
    decompress: false,
    full_address: false,
    #[cfg(feature = "context")]
    context_width_p: 0,
    #[cfg(feature = "time")]
    time_width_p: 0,
    ecause_width_p: 6,
    iaddress_lsb_p: 1,
    iaddress_width_p: 64,
    cache_size_p: 0,
    privilege_width_p: 2,
    cpu_index_width: 0,
    encoder_mode_n: 0,
    ioptions_n: 0,
};

pub struct Decoder<'a, const ADDR_BUFFER_LEN: usize, const PACKET_BUFFER_LEN: usize> {
    packet_buffer: &'a [u8; PACKET_BUFFER_LEN],
    address_buffer: &'a [u64; ADDR_BUFFER_LEN],
    bit_pos: usize,
    current_cpu_index: usize,
    conf: DecoderConfiguration,
}

// TODO DecoderConfiguration impl with Just provide the functions in non-generic implementations:  checking
// 0 <addr width < 65
// cpu index < 2^5

impl<'a> Decoder<'a, 1, 32> {
    pub fn default(conf: DecoderConfiguration) -> Self {
        Decoder::new(conf)
    }
}

impl<'a, const ADDR_BUFFER_LEN: usize, const PACKET_BUFFER_LEN: usize> Decoder<'a, ADDR_BUFFER_LEN, PACKET_BUFFER_LEN> {
    pub fn new(conf: DecoderConfiguration) -> Self {
        Decoder {
            packet_buffer: &[0; PACKET_BUFFER_LEN],
            address_buffer: &[0; ADDR_BUFFER_LEN],
            bit_pos: 0,
            current_cpu_index: 0,
            conf,
        }
    }

    pub fn decode_header(&mut self, slice: &'a [u8; PACKET_BUFFER_LEN]) -> Header {
        self.set_buffer(slice);
        let header = Header::decode(self);
        assert_eq!(header.trace_type, TraceType::Instruction);
        header
    }

    pub fn decode_payload(&mut self, header: &Header, slice: &'a [u8; PACKET_BUFFER_LEN]) -> Payload {
        self.set_buffer(slice);
        if self.conf.decompress {
            // TODO decompression
            todo!("decompression");
        }
        let format = Format::decode(self);
        self.current_cpu_index = header.cpu_index;

        let payload = match format {
            Format::Ext(Ext::BranchCount) => {
                Payload::Extension(Extension::BranchCount(BranchCount::decode(self)))
            }
            Format::Ext(Ext::JumpTargetIndex) => {
                Payload::Extension(Extension::JumpTargetIndex(JumpTargetIndex::decode(self)))
            }
            Format::Branch => Payload::Branch(Branch::decode(self)),
            Format::Addr => Payload::Address(Address::decode(self)),
            Format::Sync(Sync::Start) => {
                Payload::Synchronization(Synchronization::Start(Start::decode(self)))
            }
            Format::Sync(Sync::Trap) => {
                Payload::Synchronization(Synchronization::Trap(Trap::decode(self)))
            }
            Format::Sync(Sync::Context) => {
                Payload::Synchronization(Synchronization::Context(Context::decode(self)))
            }
            Format::Sync(Sync::Support) => {
                Payload::Synchronization(Synchronization::Support(Support::decode(self)))
            }
        };
        payload
    }

    pub fn set_buffer(&mut self, array: &'a [u8; PACKET_BUFFER_LEN]) {
        self.bit_pos = 0;
        self.packet_buffer = array
    }

    pub fn read_bit(&mut self) -> bool {
        let byte_pos = self.bit_pos / 8;
        let mut value = self.packet_buffer[byte_pos];
        value >>= self.bit_pos % 8;
        self.bit_pos += 1;
        (value & 1u8) == 0x01
    }

    pub fn read_address(&mut self) -> u64 {
        self.read(self.conf.iaddress_width_p - self.conf.iaddress_lsb_p) << self.conf.iaddress_lsb_p
    }

    pub fn read(&mut self, bit_count: usize) -> u64 {
        if bit_count == 0 {
            return 0;
        }
        assert!(bit_count <= 64);
        assert!(bit_count + self.bit_pos - 1 < PACKET_BUFFER_LEN * 8);
        let byte_pos = self.bit_pos / 8;
        let mut value = u64::from_le_bytes(self.packet_buffer[byte_pos..byte_pos + 8].try_into().unwrap());
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
            // Take 9th byte and mask MS bits we don't need
            let missing_msbs = self.packet_buffer[byte_pos + 8] & u8::MAX >> 8 - missing_bit_count;
            // shift msbs into correct position in u64 and add with previously read value
            value + ((missing_msbs as u64) << 64 - missing_bit_count)
        } else {
            value
        }
    }

    // TODO scary documentation
    // Many times read value less/equal to 32 bits
    // Return value fits into a single register
    // reading 32 bits over byte boundary will not work if read is not aligned
    pub fn read_fast(&mut self, bit_count: usize) -> u32 {
        if bit_count == 0 {
            return 0;
        }
        debug_assert!(bit_count <= 32);
        debug_assert!(bit_count + self.bit_pos - 1 < PACKET_BUFFER_LEN * 4);
        let byte_pos = self.bit_pos / 8;
        let mut value = u32::from_le_bytes(self.packet_buffer[byte_pos..byte_pos + 4].try_into().unwrap());
        value >>= self.bit_pos % 8;
        self.bit_pos += bit_count;
        if bit_count < 32 {
            value & ((1u32 << bit_count) - 1)
        } else {
            value
        }
    }
}

pub struct DecoderConfiguration {
    pub decompress: bool,
    pub full_address: bool,
    #[cfg(feature = "context")]
    pub context_width_p: usize,
    #[cfg(feature = "time")]
    pub time_width_p: usize,
    pub ecause_width_p: usize,
    pub iaddress_lsb_p: usize,
    pub iaddress_width_p: usize,
    pub cache_size_p: usize,
    pub privilege_width_p: usize,
    pub cpu_index_width: usize,
    pub encoder_mode_n: usize,
    pub ioptions_n: usize,
}

trait Decode<const ADDR_BUFFER_LEN: usize, const PACKET_BUFFER_LEN: usize> {
    fn decode(decoder: &mut Decoder<ADDR_BUFFER_LEN, PACKET_BUFFER_LEN>) -> Self;
}

#[cfg(test)]
mod tests {
    use crate::decoder::*;

    #[test_case]
    fn read_u64() {
        let mut buffer = [0; 32];
        buffer[0] = 0b01_111111;
        buffer[1] = 0b00_011111;
        buffer[2] = 0b10010010;
        buffer[3] = 0xF1;
        buffer[4] = 0xF0;
        buffer[5] = 0xF0;
        buffer[6] = 0xF0;
        buffer[7] = 0xF0;
        buffer[8] = 0xF0;
        buffer[9] = 0xFF;
        buffer[10] = 0b01_111111;
        // ...
        buffer[18] = 0b11_110000;
        let mut decoder = Decoder::default(DEFAULT_CONFIGURATION);
        decoder.set_buffer(&buffer);
        // testing for bit position
        assert_eq!(decoder.read(6), 0b111111);
        assert_eq!(decoder.bit_pos, 6);
        assert_eq!(decoder.read(2), 0b01);
        assert_eq!(decoder.bit_pos, 8);
        assert_eq!(decoder.read(6), 0b011111);
        assert_eq!(decoder.bit_pos, 14);
        // read over byte boundary
        assert_eq!(decoder.read(10), 0b1001001000);
        assert_eq!(decoder.bit_pos, 24);
        assert_eq!(decoder.read(62), 0x3F_FF_F0_F0_F0_F0_F0_F1);
        assert_eq!(decoder.bit_pos, 86);
        assert_eq!(decoder.read(64), 0xC000_0000_0000_0001);
        assert_eq!(decoder.bit_pos, 150);
    }

    #[test_case]
    fn read_entire_buffer() {
        let buffer: [u8; 32] = [255; 32];
        let mut decoder = Decoder::default(DEFAULT_CONFIGURATION);
        decoder.set_buffer(&buffer);
        assert_eq!(decoder.read(64), u64::MAX);
        assert_eq!(decoder.read(64), u64::MAX);
        assert_eq!(decoder.read(64), u64::MAX);
        assert_eq!(decoder.read(64), u64::MAX);
    }

    #[test_case]
    fn read_u32() {
        let mut buffer = [0u8; 32];
        buffer[0] = 0b1100_0101;
        buffer[1] = 0b1111_1111;
        let mut decoder = Decoder::default(DEFAULT_CONFIGURATION);
        decoder.set_buffer(&buffer);
        assert_eq!(decoder.read_fast(2), 0b01);
        assert_eq!(decoder.bit_pos, 2);
        assert_eq!(decoder.read_fast(2), 0b01);
        assert_eq!(decoder.bit_pos, 4);
        assert_eq!(decoder.read_fast(2), 0b00);
        assert_eq!(decoder.bit_pos, 6);
        assert_eq!(decoder.read_fast(1), 0b1);
        assert_eq!(decoder.bit_pos, 7);
        assert_eq!(decoder.read_fast(8), 255);
        assert_eq!(decoder.bit_pos, 15)
    }

    #[test_case]
    fn read_bool_bits() {
        let buffer: [u8; 32] = [0b0101_0101; 32];
        let mut decoder = Decoder::default(DEFAULT_CONFIGURATION);
        decoder.set_buffer(&buffer);
        assert_eq!(decoder.read_bit(), true);
        assert_eq!(decoder.read_bit(), false);
        assert_eq!(decoder.read_bit(), true);
        assert_eq!(decoder.read_bit(), false);
        assert_eq!(decoder.read_bit(), true);
        assert_eq!(decoder.read_bit(), false);
        assert_eq!(decoder.read_bit(), true);
        assert_eq!(decoder.read_bit(), false);
    }
}
