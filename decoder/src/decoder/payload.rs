use crate::decoder::{Decode, DecodeError, Decoder};
use crate::tracer::TraceErrorType;
use core::fmt;

fn read_address<const PACKET_BUFFER_LEN: usize>(
    decoder: &mut Decoder<PACKET_BUFFER_LEN>,
) -> Result<u64, DecodeError> {
    Ok(
        decoder.read(decoder.proto_conf.iaddress_width_p - decoder.proto_conf.iaddress_lsb_p)?
            << decoder.proto_conf.iaddress_lsb_p,
    )
}

fn read_branches<const PACKET_BUFFER_LEN: usize>(
    decoder: &mut Decoder<PACKET_BUFFER_LEN>,
) -> Result<usize, DecodeError> {
    let value = decoder.read(5)?;
    Ok(match value {
        0 => 0,
        1 => 1,
        2..=3 => 3,
        4..=7 => 7,
        8..=15 => 15,
        16..=31 => 31,
        _ => unreachable!(),
    })
}

pub struct ContextPart {
    pub privilege: u64,
    #[cfg(feature = "time")]
    pub time: u64,
    #[cfg(feature = "context")]
    pub context: u64,
}

impl<const PACKET_BUFFER_LEN: usize> Decode<PACKET_BUFFER_LEN> for ContextPart {
    fn decode(decoder: &mut Decoder<PACKET_BUFFER_LEN>) -> Result<Self, DecodeError> {
        Ok(ContextPart {
            privilege: decoder.read(decoder.proto_conf.privilege_width_p)?,
            #[cfg(feature = "time")]
            time: decoder.read(decoder.proto_conf.time_width_p)?,
            #[cfg(feature = "context")]
            context: decoder.read(decoder.proto_conf.context_width_p)?,
        })
    }
}

#[cfg(feature = "IR")]
pub struct IRPayload {
    pub irreport: usize,
    pub irdepth: usize,
}

#[cfg(feature = "IR")]
impl<const PACKET_BUFFER_LEN: usize> Decode<PACKET_BUFFER_LEN> for IRPayload {
    fn decode(decoder: &mut Decoder<PACKET_BUFFER_LEN>) -> Result<Self, DecodeError> {
        unimplemented!()
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Payload {
    Extension(Extension),
    Branch(Branch),
    Address(AddressInfo),
    Synchronization(Synchronization),
}

impl Payload {
    pub fn get_address_info(&self) -> Option<&AddressInfo> {
        return if let Payload::Address(addr) = self {
            Some(addr)
        } else if let Payload::Branch(branch) = self {
            branch.address.as_ref()
        } else if let Payload::Extension(Extension::BranchCount(branch_count)) = self {
            branch_count.address.as_ref()
        } else {
            None
        };
    }

    pub fn get_address(&self) -> u64 {
        match self.get_address_info() {
            None => {
                if let Payload::Synchronization(Synchronization::Start(start)) = self {
                    start.address
                } else if let Payload::Synchronization(Synchronization::Trap(trap)) = self {
                    trap.address
                } else {
                    panic!("{:?} does not have an address", self)
                }
            }
            Some(addr_info) => addr_info.address,
        }
    }

    pub fn get_branches(&self) -> Option<usize> {
        match self {
            Payload::Branch(branch) => Some(branch.branches),
            _ => None,
        }
    }

    pub fn get_privilege(&self) -> Result<u64, TraceErrorType> {
        if let Payload::Synchronization(sync) = self {
            Ok(sync.get_privilege()?)
        } else {
            Err(TraceErrorType::WrongGetPrivilegeType)
        }
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Extension {
    BranchCount(BranchCount),
    JumpTargetIndex(JumpTargetIndex),
}

// Format 0, sub format 0
#[derive(Eq, PartialEq, Copy, Clone)]
pub struct BranchCount {
    pub branch_count: u32,
    pub branch_fmt: BranchFmt,
    pub address: Option<AddressInfo>,
}

impl fmt::Debug for BranchCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "BranchCount {{ branch_count: {:x}, branch_fmt: {:?}, address: {:#0?} }}",
            self.branch_count, self.branch_fmt, self.address
        ))
    }
}

impl<const PACKET_BUFFER_LEN: usize> Decode<PACKET_BUFFER_LEN> for BranchCount {
    fn decode(decoder: &mut Decoder<PACKET_BUFFER_LEN>) -> Result<Self, DecodeError> {
        let branch_count = decoder.read(32)? - 31;
        let branch_fmt = BranchFmt::decode(decoder)?;
        let address = if branch_fmt == BranchFmt::NoAddr {
            None
        } else {
            Some(AddressInfo::decode(decoder)?)
        };
        Ok(BranchCount {
            branch_count: branch_count.try_into().unwrap(),
            address,
            branch_fmt,
        })
    }
}

#[derive(Eq, PartialEq, Debug, Copy, Clone)]
pub enum BranchFmt {
    NoAddr,
    // does not exist
    Addr,
    AddrFail,
}

impl<const PACKET_BUFFER_LEN: usize> Decode<PACKET_BUFFER_LEN> for BranchFmt {
    fn decode(decoder: &mut Decoder<PACKET_BUFFER_LEN>) -> Result<Self, DecodeError> {
        match decoder.read(2)? {
            0b00 => Ok(BranchFmt::NoAddr),
            0b01 => Err(DecodeError::BadBranchFmt),
            0b10 => Ok(BranchFmt::Addr),
            0b11 => Ok(BranchFmt::AddrFail),
            _ => unreachable!(),
        }
    }
}

/// Format 0, sub format 1
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct JumpTargetIndex {
    pub index: usize,
    pub branches: usize,
    pub branch_map: Option<u32>,
    #[cfg(feature = "IR")]
    pub irreport: usize,
    #[cfg(feature = "IR")]
    pub irdepth: usize,
}

impl<const PACKET_BUFFER_LEN: usize> Decode<PACKET_BUFFER_LEN> for JumpTargetIndex {
    fn decode(decoder: &mut Decoder<PACKET_BUFFER_LEN>) -> Result<Self, DecodeError> {
        let index = decoder.read(decoder.proto_conf.cache_size_p)? as usize;
        let branches = read_branches(decoder)?;
        let branch_map = if branches == 0 {
            None
        } else {
            Some(decoder.read(branches)?.try_into().unwrap())
        };

        #[cfg(feature = "IR")]
        let ir_payload = IRPayload::decode(decoder)?;
        Ok(JumpTargetIndex {
            index,
            branches,
            branch_map,
            #[cfg(feature = "IR")]
            irreport: ir_payload.irreport,
            #[cfg(feature = "IR")]
            irdepth: ir_payload.irdepth,
        })
    }
}

/// Format 1
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct Branch {
    pub branches: usize,
    pub branch_map: u32,
    pub address: Option<AddressInfo>,
}

impl<const PACKET_BUFFER_LEN: usize> Decode<PACKET_BUFFER_LEN> for Branch {
    fn decode(decoder: &mut Decoder<PACKET_BUFFER_LEN>) -> Result<Self, DecodeError> {
        let branches = read_branches(decoder)?;
        let branch_map = decoder
            .read(if branches == 0 { 31 } else { branches })?
            .try_into()
            .unwrap();

        let address = if branches != 0 {
            Some(AddressInfo::decode(decoder)?)
        } else {
            None
        };
        // FIXME is this correct or buggy?
        // assert!(address.is_some() && address.unwrap().address != 0);
        Ok(Branch {
            branches,
            branch_map,
            address,
        })
    }
}

/// Format 2
#[derive(Eq, PartialEq, Copy, Clone)]
pub struct AddressInfo {
    pub address: u64,
    pub notify: bool,
    pub updiscon: bool,
    #[cfg(feature = "IR")]
    pub irreport: usize,
    #[cfg(feature = "IR")]
    pub irdepth: usize,
}

impl fmt::Debug for AddressInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!(
            "AddressInfo {{ address: {:#0x}, notify: {:?}, updiscon: {:?} }}",
            self.address, self.notify, self.updiscon
        ))
    }
}

impl<const PACKET_BUFFER_LEN: usize> Decode<PACKET_BUFFER_LEN> for AddressInfo {
    fn decode(decoder: &mut Decoder<PACKET_BUFFER_LEN>) -> Result<Self, DecodeError> {
        let address = read_address(decoder)?;
        let notify = decoder.read_bit()?;
        let updiscon = decoder.read_bit()?;
        #[cfg(feature = "IR")]
        let ir_payload = IRPayload::decode(decoder)?;
        Ok(AddressInfo {
            address,
            notify,
            updiscon,
            #[cfg(feature = "IR")]
            irreport: ir_payload.irreport,
            #[cfg(feature = "IR")]
            irdepth: ir_payload.irdepth,
        })
    }
}

/// Format 0
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Synchronization {
    Start(Start),
    Trap(Trap),
    Context(Context),
    Support(Support),
}

impl Synchronization {
    pub fn get_branch(&self) -> Result<u32, TraceErrorType> {
        match self {
            Synchronization::Start(start) => Ok(start.branch),
            Synchronization::Trap(trap) => Ok(trap.branch),
            _ => Err(TraceErrorType::WrongGetBranchType(*self)),
        }
        .map(|b| b as u32)
    }

    pub fn get_privilege(&self) -> Result<u64, TraceErrorType> {
        match self {
            Synchronization::Start(start) => Ok(start.privilege),
            Synchronization::Trap(trap) => Ok(trap.privilege),
            Synchronization::Context(ctx) => Ok(ctx.privilege),
            Synchronization::Support(_) => Err(TraceErrorType::WrongGetPrivilegeType),
        }
    }
}

/// Format 0, sub format 0
#[derive(Eq, PartialEq, Copy, Clone)]
pub struct Start {
    pub branch: bool,
    pub privilege: u64,
    #[cfg(feature = "time")]
    pub time: u64,
    #[cfg(feature = "context")]
    pub context: u64,
    pub address: u64,
}

impl fmt::Debug for Start {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "Start {{ branch: {:?}, privilege: {:?}, address: {:#0x} }}",
            self.branch, self.privilege, self.address
        ))
    }
}

impl<const PACKET_BUFFER_LEN: usize> Decode<PACKET_BUFFER_LEN> for Start {
    fn decode(decoder: &mut Decoder<PACKET_BUFFER_LEN>) -> Result<Self, DecodeError> {
        let branch = decoder.read_bit()?;
        let ctx_payload = ContextPart::decode(decoder)?;
        let address = read_address(decoder)?;
        Ok(Start {
            branch,
            privilege: ctx_payload.privilege,
            #[cfg(feature = "time")]
            time: ctx_payload.time,
            #[cfg(feature = "context")]
            context: ctx_payload.context,
            address,
        })
    }
}

/// Format 0, sub format 1
#[derive(Eq, PartialEq, Copy, Clone)]
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

impl fmt::Debug for Trap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(
            format_args!("Trap {{ branch: {:?}, privilege: {:?}, ecause: {:?}, interrupt: {:?}, thaddr: {:?}, address: {:#0x}, tval: {:?} }}",
            self.branch, self.privilege, self.ecause, self.interrupt, self.thaddr, self.address, self.tval))
    }
}

impl<const PACKET_BUFFER_LEN: usize> Decode<PACKET_BUFFER_LEN> for Trap {
    fn decode(decoder: &mut Decoder<PACKET_BUFFER_LEN>) -> Result<Self, DecodeError> {
        let branch = decoder.read_bit()?;
        let ctx_payload = ContextPart::decode(decoder)?;
        let ecause = decoder.read(decoder.proto_conf.ecause_width_p)?;
        let interrupt = decoder.read_bit()?;
        let thaddr = decoder.read_bit()?;
        let address = read_address(decoder)?;
        let tval = decoder.read(decoder.proto_conf.iaddress_width_p)?;
        Ok(Trap {
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
        })
    }
}

/// Format 0, sub format 2
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct Context {
    pub privilege: u64,
    #[cfg(feature = "time")]
    pub time: u64,
    #[cfg(feature = "context")]
    pub context: u64,
}

impl<const PACKET_BUFFER_LEN: usize> Decode<PACKET_BUFFER_LEN> for Context {
    fn decode(decoder: &mut Decoder<PACKET_BUFFER_LEN>) -> Result<Self, DecodeError> {
        let ctx = ContextPart::decode(decoder)?;
        Ok(Context {
            privilege: ctx.privilege,
            #[cfg(feature = "time")]
            time: ctx.time,
            #[cfg(feature = "context")]
            context: ctx.context,
        })
    }
}

/// Format 0, sub format 3
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct Support {
    pub ienable: bool,
    pub encoder_mode: u64,
    pub qual_status: QualStatus,
    pub ioptions: u64,
    pub denable: bool,
    pub dloss: bool,
    pub doptions: u64,
}

impl<const PACKET_BUFFER_LEN: usize> Decode<PACKET_BUFFER_LEN> for Support {
    fn decode(decoder: &mut Decoder<PACKET_BUFFER_LEN>) -> Result<Self, DecodeError> {
        let ienable = decoder.read_bit()?;
        let encoder_mode = decoder.read(decoder.proto_conf.encoder_mode_n)?;
        let qual_status = QualStatus::decode(decoder)?;
        let ioptions = decoder.read(decoder.proto_conf.ioptions_n)?;
        let denable = decoder.read_bit()?;
        let dloss = decoder.read_bit()?;
        let doptions = decoder.read(4)?;
        Ok(Support {
            ienable,
            encoder_mode,
            qual_status,
            ioptions,
            denable,
            dloss,
            doptions,
        })
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum QualStatus {
    NoChange,
    EndedRep,
    TraceLost,
    EndedNtr,
}

impl<const PACKET_BUFFER_LEN: usize> Decode<PACKET_BUFFER_LEN> for QualStatus {
    fn decode(decoder: &mut Decoder<PACKET_BUFFER_LEN>) -> Result<Self, DecodeError> {
        Ok(match decoder.read(2)? {
            0b00 => QualStatus::NoChange,
            0b01 => QualStatus::EndedRep,
            0b10 => QualStatus::TraceLost,
            0b11 => QualStatus::EndedNtr,
            _ => unreachable!(),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::decoder::payload::{AddressInfo, Branch, JumpTargetIndex, Start};
    use crate::decoder::{Decode, Decoder, DEFAULT_PACKET_BUFFER_LEN};
    use crate::{ProtocolConfiguration, DEFAULT_DECODER_CONFIG, DEFAULT_PROTOCOL_CONFIG};

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
        let mut decoder = Decoder::new(
            ProtocolConfiguration {
                cache_size_p: cache_size_p_override,
                ..DEFAULT_PROTOCOL_CONFIG
            },
            DEFAULT_DECODER_CONFIG,
        );

        decoder.set_buffer(buffer);
        let jti_long = JumpTargetIndex::decode(&mut decoder).unwrap();
        assert_eq!(jti_long.index, 768);
        assert_eq!(jti_long.branches, 31);
        assert_eq!(jti_long.branch_map, Some(10));
        let jti_short = JumpTargetIndex::decode(&mut decoder).unwrap();
        assert_eq!(jti_short.index, 1023);
        assert_eq!(jti_short.branches, 0);
        assert_eq!(jti_short.branch_map, None);
    }

    #[test_case]
    fn branch() {
        let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
        buffer[0] = 0b010_00101;
        buffer[1] = 0b0000_1011;
        let mut decoder = Decoder::default();
        decoder.set_buffer(buffer);
        let branch = Branch::decode(&mut decoder).unwrap();
        assert_eq!(branch.branches, 7);
        assert_eq!(branch.branch_map, 0b1011_010);
        assert_eq!(
            branch.address,
            Some(AddressInfo {
                address: 0,
                notify: false,
                updiscon: false,
            })
        );
    }

    #[test_case]
    fn branch_with_zero_branches_has_no_addr() {
        let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
        buffer[0] = 0b000_00000;
        buffer[1] = 0b100;
        let mut decoder = Decoder::default();
        decoder.set_buffer(buffer);
        let branch_no_addr = Branch::decode(&mut decoder).unwrap();
        assert_eq!(branch_no_addr.branches, 0);
        assert_eq!(branch_no_addr.branch_map, 32);
        assert_eq!(branch_no_addr.address, None);
    }

    #[test_case]
    fn address() {
        let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
        buffer[0] = 0b0000_0001;
        buffer[7] = 0b11_000000;
        // test differential addr with second address
        buffer[8] = 0b0000_0001;
        buffer[15] = 0b10_000000;
        let mut decoder = Decoder::new(
            ProtocolConfiguration {
                // Changed address width and lsb, so that the entire
                // packet aligns with 64 bit
                iaddress_width_p: 64,
                iaddress_lsb_p: 2,
                ..DEFAULT_PROTOCOL_CONFIG
            },
            DEFAULT_DECODER_CONFIG,
        );
        decoder.set_buffer(buffer);
        let addr = AddressInfo::decode(&mut decoder).unwrap();
        assert_eq!(addr.address, 4);
        assert_eq!(addr.notify, true);
        assert_eq!(addr.updiscon, true);
        // differential address
        let diff_addr = AddressInfo::decode(&mut decoder).unwrap();
        assert_eq!(diff_addr.address, 4);
        assert_eq!(diff_addr.notify, false);
        assert_eq!(diff_addr.updiscon, true);
    }

    #[test_case]
    fn synchronization_start() {
        let buffer = [255; DEFAULT_PACKET_BUFFER_LEN];
        let mut decoder = Decoder::new(
            ProtocolConfiguration {
                iaddress_width_p: 64,
                iaddress_lsb_p: 0,
                ..DEFAULT_PROTOCOL_CONFIG
            },
            DEFAULT_DECODER_CONFIG,
        );
        decoder.set_buffer(buffer);
        let sync_start = Start::decode(&mut decoder).unwrap();
        assert_eq!(sync_start.branch, true);
        assert_eq!(sync_start.privilege, 0b11);
        assert_eq!(sync_start.address, u64::MAX);
    }
}
