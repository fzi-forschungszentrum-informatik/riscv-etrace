use crate::decoder::format::{Ext, Format, Sync};
#[cfg(feature = "IR")]
use parts::IRPayload;
use parts::{AddressPart, BranchCountPart, BranchPart, ContextPart, ShortBranchPart};

mod format;
mod parts;

#[cfg(feature = "time")]
const TIME: u64 = todo!();
#[cfg(feature = "context")]
const CONTEXT: u64 = todo!();
#[cfg(feature = "IR")]
const IR: u64 = todo!();

const BUFFER_BYTE_SIZE: usize = 32;

pub const DEFAULT_CONFIGURATION: DecoderConfiguration = DecoderConfiguration {
    decompress: false,
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

pub struct Decoder<'a> {
    buffer: &'a [u8; BUFFER_BYTE_SIZE],
    bit_pos: usize,
    conf: DecoderConfiguration,
}

// TODO DecoderConfiguration impl with checking
// 0 <addr width < 65
// cpu index < 2^5

impl<'a> Decoder<'a> {
    pub fn new(conf: DecoderConfiguration) -> Self {
        Decoder {
            buffer: &[0; BUFFER_BYTE_SIZE],
            bit_pos: 0,
            conf,
        }
    }

    pub fn decode_packet(&mut self, source: &'a [u8; BUFFER_BYTE_SIZE]) -> Packet {
        self.buffer = source;

        if self.conf.decompress {
            // TODO decompression
            todo!("decompression");
        }

        let header = Header::decode(self);
        assert_eq!(header.trace_type, TraceType::Instruction);

        let format = Format::decode(self);

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

        Packet { header, payload }
    }

    #[cfg(test)]
    fn set_buffer(&mut self, array: &'a [u8; 32]) {
        self.buffer = array
    }

    pub fn read_bool_bit(&mut self) -> bool {
        let byte_pos = self.bit_pos / 8;
        let mut value = self.buffer[byte_pos];
        value <<= self.bit_pos % 8;
        value >>= 7;
        self.bit_pos += 1;
        value == 0x01
    }

    pub fn read_address(&mut self) -> u64 {
        self.read_u64(self.conf.iaddress_width_p - self.conf.iaddress_lsb_p)
            << self.conf.iaddress_lsb_p
    }

    pub fn read_u64(&mut self, bit_count: usize) -> u64 {
        if bit_count == 0 {
            return 0;
        }
        assert!(bit_count <= 64);
        assert!(bit_count + self.bit_pos - 1 < BUFFER_BYTE_SIZE * 8);
        let byte_pos = self.bit_pos / 8;
        let mut value = u64::from_be_bytes(self.buffer[byte_pos..byte_pos + 8].try_into().unwrap());
        // Ignore first 'self.bit_pos' MSBs in first byte as they are already consumed.
        value <<= self.bit_pos % 8;
        // Reverse bits so LSB from packet is actually LSB in the number.
        value = value.reverse_bits();
        // Zero out everything except 'bit_count' LSBs.
        value = value & (u64::MAX >> (64 - bit_count));
        self.bit_pos += bit_count;
        // Check if we need to read into the 9th byte
        if self.bit_pos > ((byte_pos + 8) * 8) {
            let missing_bit_count = (self.bit_pos - ((byte_pos + 8) * 8)) % 8;
            // Take 9th byte and shift out unnecessary MSBs
            let missing_msbs = (self.buffer[byte_pos + 8]) >> 8 - missing_bit_count;
            // The unneeded bits are already shifted out so we can just add them after shifting
            // the MSBs into the proper position
            value + ((missing_msbs.reverse_bits() as u64) << 56)
        } else {
            value
        }
    }

    // TODO scary documentation
    // Many times read value less/equal to 32 bits
    // Return value fits into a single register
    // reading 32 bits over byte boundary will not work if read is not aligned
    pub fn read_fast_u32(&mut self, bit_count: usize) -> u32 {
        if bit_count == 0 {
            return 0;
        }
        debug_assert!(bit_count <= 32);
        debug_assert!(bit_count + self.bit_pos - 1 < BUFFER_BYTE_SIZE * 4);
        let byte_pos = self.bit_pos / 8;
        let mut value = u32::from_be_bytes(self.buffer[byte_pos..byte_pos + 4].try_into().unwrap());
        value <<= self.bit_pos % 8;
        self.bit_pos += bit_count;
        value = value.reverse_bits();
        value & (u32::MAX >> (32 - bit_count))
    }
}

pub struct DecoderConfiguration {
    decompress: bool,
    #[cfg(feature = "context")]
    context_width_p: usize,
    #[cfg(feature = "time")]
    time_width_p: usize,
    ecause_width_p: usize,
    iaddress_lsb_p: usize,
    iaddress_width_p: usize,
    cache_size_p: usize,
    privilege_width_p: usize,
    cpu_index_width: usize,
    encoder_mode_n: usize,
    ioptions_n: usize,
}

trait Decode {
    fn decode(decoder: &mut Decoder) -> Self;
}

#[derive(Debug, Eq, PartialEq)]
pub struct Packet {
    pub header: Header,
    pub payload: Payload,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Header {
    pub payload_length: u8,
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
            payload_length: payload_length.try_into().unwrap(),
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
            _ => panic!(),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Payload {
    Extension(Extension),
    Branch(Branch),
    Address(Address),
    Synchronization(Synchronization),
}

#[derive(Debug, Eq, PartialEq)]
pub enum Extension {
    BranchCount(BranchCount),
    JumpTargetIndex(JumpTargetIndex),
}

#[derive(Debug, Eq, PartialEq)]
pub struct BranchCount {
    pub branch_count: u32,
    pub branch_fmt: BranchFmt,
    pub address: Option<Address>,
}

impl Decode for BranchCount {
    fn decode(decoder: &mut Decoder) -> Self {
        let count_payload = BranchCountPart::decode(decoder);
        BranchCount {
            branch_count: count_payload.branch_count,
            address: if count_payload.branch_fmt == BranchFmt::NoAddr {
                None
            } else {
                Some(Address::decode(decoder))
            },
            branch_fmt: count_payload.branch_fmt,
        }
    }
}

#[derive(Eq, PartialEq, Debug)]
pub enum BranchFmt {
    NoAddr,
    // does not exist
    Addr,
    AddrFail,
}

impl Decode for BranchFmt {
    fn decode(decoder: &mut Decoder) -> Self {
        match decoder.read_fast_u32(2) {
            0b00 => BranchFmt::NoAddr,
            0b01 => panic!(),
            0b10 => BranchFmt::Addr,
            0b11 => BranchFmt::AddrFail,
            _ => panic!(),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct JumpTargetIndex {
    pub index: usize,
    pub branches: usize,
    pub branch_map: Option<u32>,
    #[cfg(feature = "IR")]
    pub irreport: usize,
    #[cfg(feature = "IR")]
    pub irdepth: usize,
}

impl Decode for JumpTargetIndex {
    fn decode(decoder: &mut Decoder) -> Self {
        let index = decoder.read_u64(decoder.conf.cache_size_p) as usize;
        let short_payload = ShortBranchPart::decode(decoder);
        #[cfg(feature = "IR")]
        let ir_payload = IRPayload::decode(decoder);
        JumpTargetIndex {
            index,
            branches: short_payload.branches,
            branch_map: short_payload.branch_map,
            #[cfg(feature = "IR")]
            irreport: ir_payload.irreport,
            #[cfg(feature = "IR")]
            irdepth: ir_payload.irdepth,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Branch {
    pub branches: usize,
    pub branch_map: u32,
    pub address: Option<Address>,
}

impl Decode for Branch {
    fn decode(decoder: &mut Decoder) -> Self {
        let branch_payload = BranchPart::decode(decoder);
        if branch_payload.branches == 0 {
            Branch {
                branches: branch_payload.branches,
                branch_map: branch_payload.branch_map,
                address: None,
            }
        } else {
            let addr = Address::decode(decoder);
            Branch {
                branches: branch_payload.branches,
                branch_map: branch_payload.branch_map,
                address: Some(addr),
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Address {
    pub address: u64,
    pub notify: bool,
    pub updiscon: bool,
    #[cfg(feature = "IR")]
    pub irreport: usize,
    #[cfg(feature = "IR")]
    pub irdepth: usize,
}

impl Decode for Address {
    fn decode(decoder: &mut Decoder) -> Self {
        let addr_payload = AddressPart::decode(decoder);
        #[cfg(feature = "IR")]
        let ir_payload = IRPayload::decode(decoder);
        Address {
            address: addr_payload.address,
            notify: addr_payload.notify,
            updiscon: addr_payload.updiscon,
            #[cfg(feature = "IR")]
            irreport: ir_payload.irreport,
            #[cfg(feature = "IR")]
            irdepth: ir_payload.irdepth,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Synchronization {
    Start(Start),
    Trap(Trap),
    Context(Context),
    Support(Support),
}

#[derive(Debug, Eq, PartialEq)]
pub struct Start {
    pub branch: bool,
    pub privilege: u64,
    #[cfg(feature = "time")]
    pub time: u64,
    #[cfg(feature = "context")]
    pub context: u64,
    pub address: u64,
}

impl Decode for Start {
    fn decode(decoder: &mut Decoder) -> Self {
        let branch = decoder.read_bool_bit();
        let ctx_payload = ContextPart::decode(decoder);
        let address = decoder.read_address();
        Start {
            branch,
            privilege: ctx_payload.privilege,
            #[cfg(feature = "time")]
            time: ctx_payload.time,
            #[cfg(feature = "context")]
            context: ctx_payload.context,
            address,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Trap {
    pub branch: bool,
    pub privilege: u64,
    #[cfg(feature = "time")]
    pub time: u64,
    #[cfg(feature = "context")]
    pub context: u64,
    pub ecause: u64,
    pub interrupt: bool,
    pub thaddr: bool,
    pub address: u64,
    pub tval: u64,
}

impl Decode for Trap {
    fn decode(decoder: &mut Decoder) -> Self {
        let branch = decoder.read_bool_bit();
        let ctx_payload = ContextPart::decode(decoder);
        let ecause = decoder.read_u64(decoder.conf.ecause_width_p);
        let interrupt = decoder.read_bool_bit();
        let thaddr = decoder.read_bool_bit();
        let address = decoder.read_address();
        let tval = decoder.read_u64(decoder.conf.iaddress_width_p);
        Trap {
            branch,
            privilege: ctx_payload.privilege,
            #[cfg(feature = "time")]
            time: ctx_payload.time,
            #[cfg(feature = "context")]
            context: ctx_payload.context,
            ecause,
            interrupt,
            thaddr,
            address,
            tval,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Context {
    pub privilege: u64,
    #[cfg(feature = "time")]
    pub time: u64,
    #[cfg(feature = "context")]
    pub context: u64,
}

impl Decode for Context {
    fn decode(decoder: &mut Decoder) -> Self {
        let ctx = ContextPart::decode(decoder);
        Context {
            privilege: ctx.privilege,
            #[cfg(feature = "time")]
            time: ctx.time,
            #[cfg(feature = "context")]
            context: ctx.context,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Support {
    pub ienable: bool,
    pub encoder_mode: u8,
    pub qual_status: QualStatus,
    pub ioptions: u8,
}

impl Decode for Support {
    fn decode(decoder: &mut Decoder) -> Self {
        let ienable = decoder.read_bool_bit();
        let encoder_mode = decoder.read_fast_u32(decoder.conf.encoder_mode_n);
        let qual_status = QualStatus::decode(decoder);
        let ioptions = decoder.read_fast_u32(decoder.conf.ioptions_n);
        Support {
            ienable,
            encoder_mode: encoder_mode.try_into().unwrap(),
            qual_status,
            ioptions: ioptions.try_into().unwrap(),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum QualStatus {
    NoChange,
    EndedRep,
    TraceLost,
    EndedNtr,
}

impl Decode for QualStatus {
    fn decode(decoder: &mut Decoder) -> Self {
        match decoder.read_fast_u32(2) {
            0b00 => QualStatus::NoChange,
            0b01 => QualStatus::EndedRep,
            0b10 => QualStatus::TraceLost,
            0b11 => QualStatus::EndedNtr,
            _ => panic!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::decoder::TraceType::Instruction;
    use crate::decoder::*;
    use crate::serial_println;
    use core::assert_matches::assert_matches;

    #[test_case]
    fn packet_support() {
        let mut buffer = [0u8; 32];
        buffer[0] = 0b11111_01_0;
        buffer[1] = 0b1111_1_000;
        buffer[2] = 0b11111_01_1;
        let mut decoder = Decoder::new(DecoderConfiguration {
            encoder_mode_n: 8,
            ioptions_n: 1,
            ..DEFAULT_CONFIGURATION
        });
        let packet = decoder.decode_packet(&buffer);
        assert_eq!(packet.header.payload_length, 31);
        assert_eq!(packet.header.trace_type, Instruction);
        assert_eq!(packet.header.has_timestamp, false);
        assert_eq!(packet.header.cpu_index, 0);
        assert_matches!(
            packet.payload,
            Payload::Synchronization(Synchronization::Support(_))
        );
        let supp = match packet.payload {
            Payload::Synchronization(Synchronization::Support(supp)) => supp,
            _ => unreachable!(),
        };
        assert_eq!(supp.ienable, true);
        assert_eq!(supp.encoder_mode, 0xF8);
        assert_eq!(supp.qual_status, QualStatus::TraceLost);
        assert_eq!(supp.ioptions, 1);
    }

    #[test_case]
    fn read_u64() {
        let mut buffer = [0; 32];
        buffer[0] = 0b111111_01;
        buffer[1] = 0b1111_1010;
        buffer[2] = 0b1001_0010;
        buffer[3] = 0xF1;
        buffer[4] = 0xF0;
        buffer[5] = 0xF0;
        buffer[6] = 0xF0;
        buffer[7] = 0xF0;
        buffer[8] = 0xF0;
        buffer[9] = 0xFF;
        buffer[10] = 0xF_2;
        // ...
        // last two bits are set to make sure they are not read
        buffer[18] = 0b000011_11;
        let mut decoder = Decoder::new(DEFAULT_CONFIGURATION);
        decoder.set_buffer(&buffer);
        // testing for position values
        assert_eq!(decoder.read_u64(6), 0b111111);
        assert_eq!(decoder.bit_pos, 6);
        assert_eq!(decoder.read_u64(2), 0b10);
        assert_eq!(decoder.bit_pos, 8);
        assert_eq!(decoder.read_u64(6), 0b011111);
        assert_eq!(decoder.bit_pos, 14);
        // read over byte boundary
        assert_eq!(decoder.read_u64(10), 0b01_0010_0101);
        assert_eq!(decoder.bit_pos, 24);
        assert_eq!(decoder.read_u64(62), 0x0FFF_0F0F_0F0F_0F8F);
        assert_eq!(decoder.bit_pos, 86);
        assert_eq!(decoder.read_u64(64), 0xC000_0000_0000_0001);
        assert_eq!(decoder.bit_pos, 150);
    }

    #[test_case]
    fn read_u32() {
        let mut buffer = [0u8; 32];
        buffer[0] = 0b1100_0101;
        buffer[1] = 0b1111_1111;
        let mut decoder = Decoder::new(DEFAULT_CONFIGURATION);
        decoder.set_buffer(&buffer);
        assert_eq!(decoder.read_fast_u32(2), 0b11);
        assert_eq!(decoder.bit_pos, 2);
        assert_eq!(decoder.read_fast_u32(2), 0b00);
        assert_eq!(decoder.bit_pos, 4);
        assert_eq!(decoder.read_fast_u32(2), 0b10);
        assert_eq!(decoder.bit_pos, 6);
        assert_eq!(decoder.read_fast_u32(1), 0b0);
        assert_eq!(decoder.bit_pos, 7);
        assert_eq!(decoder.read_fast_u32(2), 0b11);
    }

    #[test_case]
    fn read_entire_buffer() {
        let buffer: [u8; 32] = [255; 32];
        let mut decoder = Decoder::new(DEFAULT_CONFIGURATION);
        decoder.set_buffer(&buffer);
        assert_eq!(decoder.read_u64(64), u64::MAX);
        assert_eq!(decoder.read_u64(64), u64::MAX);
        assert_eq!(decoder.read_u64(64), u64::MAX);
        assert_eq!(decoder.read_u64(64), u64::MAX);
    }

    #[test_case]
    fn read_bool_bits() {
        let buffer: [u8; 32] = [0b0101_1010; 32];
        let mut decoder = Decoder::new(DEFAULT_CONFIGURATION);
        decoder.set_buffer(&buffer);
        assert_eq!(decoder.read_bool_bit(), false);
        assert_eq!(decoder.read_bool_bit(), true);
        assert_eq!(decoder.read_bool_bit(), false);
        assert_eq!(decoder.read_bool_bit(), true);
        assert_eq!(decoder.read_bool_bit(), true);
        assert_eq!(decoder.read_bool_bit(), false);
        assert_eq!(decoder.read_bool_bit(), true);
        assert_eq!(decoder.read_bool_bit(), false);
    }

    #[test_case]
    fn extension_jti() {
        let cache_size_p_override = 10;
        let mut buffer: [u8; 32] = [0; 32];
        buffer[0] = 0b00000000;
        buffer[1] = 0b11_10011_0;
        buffer[2] = 0b1010_0000;
        // ...
        buffer[5] = 0b000000_11;
        buffer[6] = 0b11111111;
        let mut decoder = Decoder::new(DecoderConfiguration {
            cache_size_p: cache_size_p_override,
            ..DEFAULT_CONFIGURATION
        });
        decoder.set_buffer(&buffer);
        let jti_long = JumpTargetIndex::decode(&mut decoder);
        assert_eq!(jti_long.index, 768);
        assert_eq!(jti_long.branches, 31);
        assert_eq!(jti_long.branch_map, Some(0b1010));
        let jti_short = JumpTargetIndex::decode(&mut decoder);
        assert_eq!(jti_short.index, 1023);
        assert_eq!(jti_short.branches, 0);
        assert_eq!(jti_short.branch_map, None);
    }

    #[test_case]
    fn branch() {
        let mut buffer: [u8; 32] = [0; 32];
        buffer[0] = 0b10100_010;
        buffer[1] = 0b1101_0000;
        let mut decoder = Decoder::new(DEFAULT_CONFIGURATION);
        decoder.set_buffer(&buffer);
        let branch = Branch::decode(&mut decoder);
        assert_eq!(branch.branches, 7);
        assert_eq!(branch.branch_map, 0b1011_010);
        assert_eq!(
            branch.address,
            Some(Address {
                address: 0,
                notify: false,
                updiscon: false,
            })
        );
    }

    #[test_case]
    fn address() {
        let mut buffer: [u8; 32] = [0; 32];
        buffer[0] = 0b1000_0000;
        buffer[1] = 0b0000_0000;
        buffer[2] = 0b0000_0000;
        buffer[3] = 0b0000_0000;
        // ...
        buffer[7] = 0b0000_0001;
        buffer[8] = 0b1000_0000;
        let mut decoder = Decoder::new(DEFAULT_CONFIGURATION);
        decoder.set_buffer(&buffer);
        let addr = Address::decode(&mut decoder);
        assert_eq!(addr.address, 2);
        assert_eq!(addr.notify, true);
        assert_eq!(addr.updiscon, true);
    }

    #[test_case]
    fn synchronization_start() {
        let buffer = [255u8; 32];
        let mut decoder = Decoder::new(DecoderConfiguration {
            iaddress_width_p: 64,
            iaddress_lsb_p: 0,
            ..DEFAULT_CONFIGURATION
        });
        decoder.set_buffer(&buffer);
        let sync_start = Start::decode(&mut decoder);
        assert_eq!(sync_start.branch, true);
        assert_eq!(sync_start.privilege, 0b11);
        assert_eq!(sync_start.address, u64::MAX);
    }
}
