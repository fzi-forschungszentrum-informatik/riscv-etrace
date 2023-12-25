use crate::decoder::{Decode, Decoder};

pub struct ContextPart {
    pub privilege: u64,
    #[cfg(feature = "time")]
    pub time: u64,
    #[cfg(feature = "context")]
    pub context: u64,
}

impl<const PC_BUFFER_LEN: usize, const PACKET_BUFFER_LEN: usize>
    Decode<PC_BUFFER_LEN, PACKET_BUFFER_LEN> for ContextPart
{
    fn decode(decoder: &mut Decoder<PC_BUFFER_LEN, PACKET_BUFFER_LEN>) -> Self {
        ContextPart {
            privilege: decoder.read(decoder.conf.privilege_width_p),
            #[cfg(feature = "time")]
            time: decoder.read(decoder.conf.time_width_p),
            #[cfg(feature = "context")]
            context: decoder.read(decoder.conf.context_width_p),
        }
    }
}

pub struct AddressPart {
    pub address: u64,
    pub notify: bool,
    pub updiscon: bool,
}

impl<const PC_BUFFER_LEN: usize, const PACKET_BUFFER_LEN: usize>
    Decode<PC_BUFFER_LEN, PACKET_BUFFER_LEN> for AddressPart
{
    fn decode(decoder: &mut Decoder<PC_BUFFER_LEN, PACKET_BUFFER_LEN>) -> Self {
        AddressPart {
            address: decoder.read_address(),
            notify: decoder.read_bit(),
            updiscon: decoder.read_bit(),
        }
    }
}

#[cfg(feature = "IR")]
pub struct IRPayload {
    pub irreport: usize,
    pub irdepth: usize,
}

#[cfg(feature = "IR")]
impl<const PC_BUFFER_LEN: usize, const PACKET_BUFFER_LEN: usize>
    Decode<PC_BUFFER_LEN, PACKET_BUFFER_LEN> for IRPayload
{
    fn decode(decoder: &mut Decoder<PC_BUFFER_LEN, PACKET_BUFFER_LEN>) -> Self {
        unimplemented!()
    }
}

pub struct BranchPart {
    pub branches: usize,
    pub branch_map: u32,
}

impl<const PC_BUFFER_LEN: usize, const PACKET_BUFFER_LEN: usize>
    Decode<PC_BUFFER_LEN, PACKET_BUFFER_LEN> for BranchPart
{
    fn decode(decoder: &mut Decoder<PC_BUFFER_LEN, PACKET_BUFFER_LEN>) -> Self {
        let branches = match decoder.read_fast(5) {
            0 => 31,
            1 => 1,
            2..=3 => 3,
            4..=7 => 7,
            8..=15 => 15,
            16..=31 => 31,
            err => panic!("This should never happen. Branches is {:?}", err),
        };
        BranchPart {
            branches,
            branch_map: decoder.read(branches).try_into().unwrap(),
        }
    }
}

pub struct BranchCountPart {
    pub branch_count: u32,
    pub branch_fmt: BranchFmt,
}

impl<const PC_BUFFER_LEN: usize, const PACKET_BUFFER_LEN: usize>
    Decode<PC_BUFFER_LEN, PACKET_BUFFER_LEN> for BranchCountPart
{
    fn decode(decoder: &mut Decoder<PC_BUFFER_LEN, PACKET_BUFFER_LEN>) -> Self {
        // FIXME too large read_fast
        let branch_count = decoder.read_fast(32) - 31;
        let branch_fmt = BranchFmt::decode(decoder);
        BranchCountPart {
            branch_count,
            branch_fmt,
        }
    }
}

pub struct ShortBranchPart {
    pub branches: usize,
    pub branch_map: Option<u32>,
}

impl<const PC_BUFFER_LEN: usize, const PACKET_BUFFER_LEN: usize>
    Decode<PC_BUFFER_LEN, PACKET_BUFFER_LEN> for ShortBranchPart
{
    fn decode(decoder: &mut Decoder<PC_BUFFER_LEN, PACKET_BUFFER_LEN>) -> Self {
        let branches = match decoder.read_fast(5) {
            0 => 0,
            1 => 1,
            2..=3 => 3,
            4..=7 => 7,
            8..=15 => 15,
            16..=31 => 31,
            err => panic!("This should never happen. Branches is {:?}", err),
        };
        ShortBranchPart {
            branches,
            branch_map: if branches == 0 {
                None
            } else {
                Some(decoder.read(branches).try_into().unwrap())
            },
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

// Format 0, sub format 0
#[derive(Debug, Eq, PartialEq)]
pub struct BranchCount {
    pub branch_count: u32,
    pub branch_fmt: BranchFmt,
    pub address: Option<Address>,
}

impl<const PC_BUFFER_LEN: usize, const PACKET_BUFFER_LEN: usize>
    Decode<PC_BUFFER_LEN, PACKET_BUFFER_LEN> for BranchCount
{
    fn decode(decoder: &mut Decoder<PC_BUFFER_LEN, PACKET_BUFFER_LEN>) -> Self {
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

impl<const PC_BUFFER_LEN: usize, const PACKET_BUFFER_LEN: usize>
    Decode<PC_BUFFER_LEN, PACKET_BUFFER_LEN> for BranchFmt
{
    fn decode(decoder: &mut Decoder<PC_BUFFER_LEN, PACKET_BUFFER_LEN>) -> Self {
        match decoder.read_fast(2) {
            0b00 => BranchFmt::NoAddr,
            0b01 => panic!("BranchFmt cannot be 0b01"),
            0b10 => BranchFmt::Addr,
            0b11 => BranchFmt::AddrFail,
            err => panic!("This should never happen. BranchFmt is {:?}", err),
        }
    }
}

/// Format 0, sub format 1
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

impl<const PC_BUFFER_LEN: usize, const PACKET_BUFFER_LEN: usize>
    Decode<PC_BUFFER_LEN, PACKET_BUFFER_LEN> for JumpTargetIndex
{
    fn decode(decoder: &mut Decoder<PC_BUFFER_LEN, PACKET_BUFFER_LEN>) -> Self {
        let index = decoder.read(decoder.conf.cache_size_p) as usize;
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

/// Format 1
#[derive(Debug, Eq, PartialEq)]
pub struct Branch {
    pub branches: usize,
    pub branch_map: u32,
    pub address: Option<Address>,
}

impl<const PC_BUFFER_LEN: usize, const PACKET_BUFFER_LEN: usize>
    Decode<PC_BUFFER_LEN, PACKET_BUFFER_LEN> for Branch
{
    fn decode(decoder: &mut Decoder<PC_BUFFER_LEN, PACKET_BUFFER_LEN>) -> Self {
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

/// Format 2
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

impl<const PC_BUFFER_LEN: usize, const PACKET_BUFFER_LEN: usize>
    Decode<PC_BUFFER_LEN, PACKET_BUFFER_LEN> for Address
{
    fn decode(decoder: &mut Decoder<PC_BUFFER_LEN, PACKET_BUFFER_LEN>) -> Self {
        let part = AddressPart::decode(decoder);
        #[cfg(feature = "IR")]
        let ir_payload = IRPayload::decode(decoder);
        Address {
            address: if decoder.conf.full_address {
                part.address
            } else {
                let addr = decoder.pc_buffer[decoder.current_cpu_index] + part.address;
                decoder.pc_buffer[decoder.current_cpu_index] = addr;
                addr
            },
            notify: part.notify,
            updiscon: part.updiscon,
            #[cfg(feature = "IR")]
            irreport: ir_payload.irreport,
            #[cfg(feature = "IR")]
            irdepth: ir_payload.irdepth,
        }
    }
}

/// Format 0
#[derive(Debug, Eq, PartialEq)]
pub enum Synchronization {
    Start(Start),
    Trap(Trap),
    Context(Context),
    Support(Support),
}

/// Format 0, sub format 0
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

impl<const PC_BUFFER_LEN: usize, const PACKET_BUFFER_LEN: usize>
    Decode<PC_BUFFER_LEN, PACKET_BUFFER_LEN> for Start
{
    fn decode(decoder: &mut Decoder<PC_BUFFER_LEN, PACKET_BUFFER_LEN>) -> Self {
        let branch = decoder.read_bit();
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

/// Format 0, sub format 1
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

impl<const PC_BUFFER_LEN: usize, const PACKET_BUFFER_LEN: usize>
    Decode<PC_BUFFER_LEN, PACKET_BUFFER_LEN> for Trap
{
    fn decode(decoder: &mut Decoder<PC_BUFFER_LEN, PACKET_BUFFER_LEN>) -> Self {
        let branch = decoder.read_bit();
        let ctx_payload = ContextPart::decode(decoder);
        let ecause = decoder.read(decoder.conf.ecause_width_p);
        let interrupt = decoder.read_bit();
        let thaddr = decoder.read_bit();
        let address = decoder.read_address();
        let tval = decoder.read(decoder.conf.iaddress_width_p);
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

/// Format 0, sub format 2
#[derive(Debug, Eq, PartialEq)]
pub struct Context {
    pub privilege: u64,
    #[cfg(feature = "time")]
    pub time: u64,
    #[cfg(feature = "context")]
    pub context: u64,
}

impl<const PC_BUFFER_LEN: usize, const PACKET_BUFFER_LEN: usize>
    Decode<PC_BUFFER_LEN, PACKET_BUFFER_LEN> for Context
{
    fn decode(decoder: &mut Decoder<PC_BUFFER_LEN, PACKET_BUFFER_LEN>) -> Self {
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

/// Format 0, sub format 3
#[derive(Debug, Eq, PartialEq)]
pub struct Support {
    pub ienable: bool,
    pub encoder_mode: u8,
    pub qual_status: QualStatus,
    pub ioptions: u8,
}

impl<const PC_BUFFER_LEN: usize, const PACKET_BUFFER_LEN: usize>
    Decode<PC_BUFFER_LEN, PACKET_BUFFER_LEN> for Support
{
    fn decode(decoder: &mut Decoder<PC_BUFFER_LEN, PACKET_BUFFER_LEN>) -> Self {
        let ienable = decoder.read_bit();
        let encoder_mode = decoder.read_fast(decoder.conf.encoder_mode_n);
        let qual_status = QualStatus::decode(decoder);
        let ioptions = decoder.read_fast(decoder.conf.ioptions_n);
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

impl<const PC_BUFFER_LEN: usize, const PACKET_BUFFER_LEN: usize>
    Decode<PC_BUFFER_LEN, PACKET_BUFFER_LEN> for QualStatus
{
    fn decode(decoder: &mut Decoder<PC_BUFFER_LEN, PACKET_BUFFER_LEN>) -> Self {
        match decoder.read_fast(2) {
            0b00 => QualStatus::NoChange,
            0b01 => QualStatus::EndedRep,
            0b10 => QualStatus::TraceLost,
            0b11 => QualStatus::EndedNtr,
            err => panic!("This should never happen. QualStatus is {:?}", err),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::decoder::payload::{Address, Branch, JumpTargetIndex, Start};
    use crate::decoder::{
        Decode, Decoder, DecoderConfiguration, DEFAULT_CONFIGURATION, DEFAULT_CPU_COUNT,
        DEFAULT_PACKET_BUFFER_LEN,
    };
    use crate::serial_println;

    #[test_case]
    fn extension_jti() {
        let cache_size_p_override = 10;
        let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
        buffer[0] = 0b00000000;
        buffer[1] = 0b0_11111_11;
        buffer[2] = 0b00000_101;
        // ...
        buffer[5] = 0b11_000000;
        buffer[6] = 0b11111111;
        let packet_buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
        let mut pc_buffer = [0; DEFAULT_CPU_COUNT];
        let mut decoder = Decoder::default(
            DecoderConfiguration {
                cache_size_p: cache_size_p_override,
                ..DEFAULT_CONFIGURATION
            },
            &packet_buffer,
            &mut pc_buffer,
        );

        decoder.set_buffer(&buffer);
        let jti_long = JumpTargetIndex::decode(&mut decoder);
        assert_eq!(jti_long.index, 768);
        assert_eq!(jti_long.branches, 31);
        assert_eq!(jti_long.branch_map, Some(10));
        let jti_short = JumpTargetIndex::decode(&mut decoder);
        assert_eq!(jti_short.index, 1023);
        assert_eq!(jti_short.branches, 0);
        assert_eq!(jti_short.branch_map, None);
    }

    #[test_case]
    fn branch() {
        let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
        buffer[0] = 0b010_00101;
        buffer[1] = 0b0000_1011;
        let packet_buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
        let mut pc_buffer = [0; DEFAULT_CPU_COUNT];
        let mut decoder = Decoder::default(DEFAULT_CONFIGURATION, &packet_buffer, &mut pc_buffer);
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
        let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
        buffer[0] = 0b0000_0001;
        buffer[7] = 0b11_000000;
        // test differential addr with second address
        buffer[8] = 0b0000_0001;
        buffer[15] = 0b1_0000000;
        let packet_buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
        let mut pc_buffer = [0; DEFAULT_CPU_COUNT];
        let mut decoder = Decoder::default(
            DecoderConfiguration {
                // Changed address width and lsb, so that the entire
                // packet aligns with 64 bit
                iaddress_width_p: 64,
                iaddress_lsb_p: 2,
                full_address: false,
                ..DEFAULT_CONFIGURATION
            },
            &packet_buffer,
            &mut pc_buffer,
        );
        decoder.set_buffer(&buffer);
        assert_eq!(decoder.current_cpu_index, 0);
        assert_eq!(decoder.pc_buffer[0], 0);
        let addr = Address::decode(&mut decoder);
        assert_eq!(addr.address, 4);
        assert_eq!(decoder.pc_buffer[0], 4);
        assert_eq!(addr.notify, true);
        assert_eq!(addr.updiscon, true);
        // differential address
        let diff_addr = Address::decode(&mut decoder);
        assert_eq!(diff_addr.address, 8);
        assert_eq!(decoder.pc_buffer[0], 8);
    }

    #[test_case]
    fn synchronization_start() {
        let buffer = [255; DEFAULT_PACKET_BUFFER_LEN];
        let packet_buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
        let mut pc_buffer = [0; DEFAULT_CPU_COUNT];
        let mut decoder = Decoder::default(
            DecoderConfiguration {
                iaddress_width_p: 64,
                iaddress_lsb_p: 0,
                ..DEFAULT_CONFIGURATION
            },
            &packet_buffer,
            &mut pc_buffer,
        );
        decoder.set_buffer(&buffer);
        let sync_start = Start::decode(&mut decoder);
        assert_eq!(sync_start.branch, true);
        assert_eq!(sync_start.privilege, 0b11);
        assert_eq!(sync_start.address, u64::MAX);
    }
}
