// Copyright (C) 2024 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0

//! Implements all different payloads and their decoding.
use crate::decoder::{Decode, DecodeError, Decoder};
use crate::tracer::TraceErrorType;

use core::fmt;

fn read_address(decoder: &mut Decoder, slice: &[u8]) -> Result<u64, DecodeError> {
    Ok(decoder.read(
        decoder.proto_conf.iaddress_width_p - decoder.proto_conf.iaddress_lsb_p,
        slice,
    )? << decoder.proto_conf.iaddress_lsb_p)
}

fn read_branches(decoder: &mut Decoder, slice: &[u8]) -> Result<(u8, usize), DecodeError> {
    let branches = decoder.read(5, slice)?.try_into().unwrap();
    let len = match branches {
        0 => 0,
        1 => 1,
        2..=3 => 3,
        4..=7 => 7,
        8..=15 => 15,
        16..=31 => 31,
        _ => unreachable!(),
    };
    Ok((branches, len))
}

/// The possible privilege levels with which the instruction was executed.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Privilege {
    User = 0b00,
    Supervisor = 0b01,
    Machine = 0b11,
}

impl Decode for Privilege {
    fn decode(decoder: &mut Decoder, slice: &[u8]) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        match decoder.read(2, slice)? {
            0b00 => Ok(Privilege::User),
            0b01 => Ok(Privilege::Supervisor),
            0b11 => Ok(Privilege::Machine),
            err => Err(DecodeError::UnknownPrivilege(err as u8)),
        }
    }
}

/// Determines the layout of [BranchCount].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BranchFmt {
    /// Packet does not contain an address, and the branch following the last correct prediction
    /// failed.
    NoAddr = 0,
    /// Packet contains an address. If this points to a branch instruction, then the
    /// branch was predicted correctly
    Addr = 2,
    /// Packet contains an address that points to a branch which failed the prediction.
    AddrFail = 3,
}

impl Decode for BranchFmt {
    fn decode(decoder: &mut Decoder, slice: &[u8]) -> Result<Self, DecodeError> {
        match decoder.read(2, slice)? {
            0b00 => Ok(BranchFmt::NoAddr),
            0b01 => Err(DecodeError::BadBranchFmt),
            0b10 => Ok(BranchFmt::Addr),
            0b11 => Ok(BranchFmt::AddrFail),
            _ => unreachable!(),
        }
    }
}

/// Reports how or if the filter qualification changed.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum QualStatus {
    /// No change to filter qualification.
    NoChange,
    /// Qualification ended, preceding packet sent explicitly to indicate last qualification
    /// instruction.
    EndedRep,
    /// One or more instruction trace packets lost.
    TraceLost,
    /// Qualification ended, preceding packet    would have been sent anyway due to an updiscon,
    /// even if it wasn’t the last qualified instruction
    EndedNtr,
}

impl Decode for QualStatus {
    fn decode(decoder: &mut Decoder, slice: &[u8]) -> Result<Self, DecodeError> {
        Ok(match decoder.read(2, slice)? {
            0b00 => QualStatus::NoChange,
            0b01 => QualStatus::EndedRep,
            0b10 => QualStatus::TraceLost,
            0b11 => QualStatus::EndedNtr,
            _ => unreachable!(),
        })
    }
}

#[cfg(feature = "implicit_return")]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ImplicitReturn {
    /// If the value of this bit is different from the previous bit in the same packet,
    /// it indicates that this packet is reporting an instruction that is either:
    /// <ul>
    /// <li>following a return because its address differs from the predicted return address at the
    /// top of the implicit_return return address stack, or</li>
    /// <li>the last retired before an exception, interrupt, privilege change or resync because it
    /// is necessary to report the current address stack depth or nested call count.</li>
    /// </ul>
    pub irreport: bool,
    /// If the value of irreport is different from previous bit in the same packet,
    /// this field indicates the number of entries on the return address stack (i.e. the entry
    /// number of the return that failed) or nested call count. If irreport is the same value as
    /// updiscon, all bits in this field will also be the same value as updiscon.
    pub irdepth: u64,
}

#[cfg(feature = "implicit_return")]
impl Decode for ImplicitReturn {
    fn decode(decoder: &mut Decoder, slice: &[u8]) -> Result<Self, DecodeError> {
        let irreport = decoder.read_bit(slice)?;
        let irdepth_len = decoder.proto_conf.return_stack_size_p
            + decoder.proto_conf.call_counter_size_p
            + (if decoder.proto_conf.return_stack_size_p > 0 {
                1
            } else {
                0
            });
        let irdepth = decoder.read(irdepth_len as usize, slice)?;
        Ok(ImplicitReturn { irreport, irdepth })
    }
}

/// Top level enum for all possible payload formats.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
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

    #[cfg(feature = "implicit_return")]
    pub fn get_implicit_return(&self) -> Option<ImplicitReturn> {
        if let Payload::Address(addr) = self {
            return Some(addr.ir);
        } else if let Payload::Branch(branch) = self {
            if let Some(addr) = branch.address {
                return Some(addr.ir);
            }
        } else if let Payload::Extension(ext) = self {
            return match ext {
                Extension::BranchCount(bc) => {
                    if let Some(addr) = bc.address {
                        Some(addr.ir)
                    } else {
                        None
                    }
                },
                Extension::JumpTargetIndex(jti) => Some(jti.ir)
            }
        }
        return None
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

    pub fn get_branches(&self) -> Option<u8> {
        match self {
            Payload::Branch(branch) => Some(branch.branches),
            _ => None,
        }
    }

    pub fn get_privilege(&self) -> Result<&Privilege, TraceErrorType> {
        if let Payload::Synchronization(sync) = self {
            Ok(sync.get_privilege()?)
        } else {
            Err(TraceErrorType::WrongGetPrivilegeType)
        }
    }
}

/// #### Format 0
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Extension {
    BranchCount(BranchCount),
    JumpTargetIndex(JumpTargetIndex),
}

/// #### Format 0, sub format 0
/// Extension to report the number of correctly predicted branches.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct BranchCount {
    /// Count of the number of correctly predicted branches, minus 31.
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

impl Decode for BranchCount {
    fn decode(decoder: &mut Decoder, slice: &[u8]) -> Result<Self, DecodeError> {
        let branch_count = decoder.read(32, slice)? - 31;
        let branch_fmt = BranchFmt::decode(decoder, slice)?;
        let address = if branch_fmt == BranchFmt::NoAddr {
            None
        } else {
            Some(AddressInfo::decode(decoder, slice)?)
        };
        Ok(BranchCount {
            branch_count: branch_count.try_into().unwrap(),
            address,
            branch_fmt,
        })
    }
}

/// #### Format 0, sub format 1
/// Extension to report the jump target index.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct JumpTargetIndex {
    /// Jump target cache index of entry containing target address.
    pub index: usize,
    /// Number of valid bits in `branch_map`.
    pub branches: usize,
    /// An array of bits indicating whether branches are taken (true) or not (false).
    pub branch_map: Option<u32>,
    #[cfg(feature = "implicit_return")]
    pub ir: ImplicitReturn,
}

impl Decode for JumpTargetIndex {
    fn decode(decoder: &mut Decoder, slice: &[u8]) -> Result<Self, DecodeError> {
        let index = usize::try_from(decoder.read(decoder.proto_conf.cache_size_p, slice)?).unwrap();
        let (branches, branch_map_len) = read_branches(decoder, slice)?;
        let branch_map = if branch_map_len == 0 {
            None
        } else {
            let branch_map: u32 = decoder.read(branch_map_len, slice)?.try_into().unwrap();
            Some(branch_map & ((1 << branches) - 1))
        };

        #[cfg(feature = "implicit_return")]
        let ir = ImplicitReturn::decode(decoder, slice)?;
        Ok(JumpTargetIndex {
            index,
            branches: branch_map_len,
            branch_map,
            #[cfg(feature = "implicit_return")]
            ir,
        })
    }
}

/// #### Format 1
/// This packet includes branch information, and is used when either the branch information must be
/// reported (for example because the branch map is full), or when the address of an instruction must
/// be reported, and there has been at least one branch since the previous packet
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Branch {
    /// Number of valid bits branch_map.
    pub branches: u8,
    /// An array of bits indicating whether branches are taken (false) or not (true).
    pub branch_map: u32,
    pub address: Option<AddressInfo>,
}

impl Decode for Branch {
    fn decode(decoder: &mut Decoder, slice: &[u8]) -> Result<Self, DecodeError> {
        let (branches, branch_map_len) = read_branches(decoder, slice)?;
        let branch_map = if branch_map_len == 0 {
            decoder.read(31, slice)? as u32
        } else {
            let too_long = decoder.read(branch_map_len, slice)? as u32;
            too_long & ((1 << branches) - 1)
        };

        let address = if branch_map_len != 0 {
            Some(AddressInfo::decode(decoder, slice)?)
        } else {
            None
        };
        Ok(Branch {
            branches,
            branch_map,
            address,
        })
    }
}

impl fmt::Debug for Branch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "Branch {{ branches: {}, branch_map: 0b{:b}, adress: {:?} }}",
            self.branches, self.branch_map, self.address
        ))
    }
}

/// #### Format 2
/// This packet contains only an instruction address, and is used when the address of an instruction
/// must be reported, and there is no unreported branch information. The address is in differential
/// format unless full address mode is enabled.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct AddressInfo {
    /// Differential instruction address.
    pub address: u64,
    /// If the value of this bit is different from the MSB of address, it indicates that this packet
    /// is reporting an instruction that is not the target of an uninferable
    /// discontinuity because a notification was requested via a trigger.
    pub notify: bool,
    /// If the value of this bit is different from notify, it indicates that this packet is
    /// reporting the instruction following an uninferable discontinuity and is also the
    /// instruction before an exception, privilege change or resync (i.e. it will be followed
    /// immediately by a format 3 packet).
    pub updiscon: bool,
    #[cfg(feature = "implicit_return")]
    pub ir: ImplicitReturn,
}

impl Decode for AddressInfo {
    fn decode(decoder: &mut Decoder, slice: &[u8]) -> Result<Self, DecodeError> {
        let address = read_address(decoder, slice)?;
        let notify = decoder.read_bit(slice)?;
        let updiscon = decoder.read_bit(slice)?;
        #[cfg(feature = "implicit_return")]
        let ir = ImplicitReturn::decode(decoder, slice)?;
        Ok(AddressInfo {
            address,
            notify,
            updiscon,
            #[cfg(feature = "implicit_return")]
            ir,
        })
    }
}

impl fmt::Debug for AddressInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "AddressInfo {{ address: {:#0x}, notify: {:?}, updiscon: {:?} }}",
            self.address, self.notify, self.updiscon
        ))
    }
}

/// #### Format 3
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
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
            _ => Err(TraceErrorType::WrongGetBranchType),
        }
        .map(|b| b as u32)
    }

    pub fn get_privilege(&self) -> Result<&Privilege, TraceErrorType> {
        match self {
            Synchronization::Start(start) => Ok(&start.ctx.privilege),
            Synchronization::Trap(trap) => Ok(&trap.ctx.privilege),
            Synchronization::Context(ctx) => Ok(&ctx.privilege),
            Synchronization::Support(_) => Err(TraceErrorType::WrongGetPrivilegeType),
        }
    }
}

/// #### Format 3, sub format 0
/// Sent for the first traced instruction or when resynchronization is necessary.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Start {
    /// False, if the address is a taken branch instruction. True, if the branch was not taken
    /// or the instruction is not a branch.
    pub branch: bool,
    pub ctx: Context,
    /// Full address of the instruction.
    pub address: u64,
}

impl Decode for Start {
    fn decode(decoder: &mut Decoder, slice: &[u8]) -> Result<Self, DecodeError> {
        let branch = decoder.read_bit(slice)?;
        let ctx = Context::decode(decoder, slice)?;
        let address = read_address(decoder, slice)?;
        Ok(Start {
            branch,
            ctx,
            address,
        })
    }
}

impl fmt::Debug for Start {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "Start {{ branch: {:?}, privilege: {:?}, address: {:#0x} }}",
            self.branch, self.ctx.privilege, self.address
        ))
    }
}

/// #### Format 3, sub format 1
/// Sent following an exception or interrupt.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Trap {
    /// False, if the address is a taken branch instruction. True, if the branch was not taken
    /// or the instruction is not a branch.
    pub branch: bool,
    pub ctx: Context,
    pub ecause: u64,
    pub interrupt: bool,
    /// True, if the address points to the trap handler. False, if address points to the EPC for
    /// an exception at the target of an updiscon, and is undefined for other exceptions and interrupts.
    pub thaddr: bool,
    /// Full address of the instruction.
    pub address: u64,
    /// Value from appropriate *tval CSR.
    pub tval: u64,
}

impl fmt::Debug for Trap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(
            format_args!("Trap {{ branch: {:?}, privilege: {:?}, ecause: {:?}, interrupt: {:?}, thaddr: {:?}, address: {:#0x}, tval: {:?} }}",
            self.branch, self.ctx.privilege, self.ecause, self.interrupt, self.thaddr, self.address, self.tval))
    }
}

impl Decode for Trap {
    fn decode(decoder: &mut Decoder, slice: &[u8]) -> Result<Self, DecodeError> {
        let branch = decoder.read_bit(slice)?;
        let ctx = Context::decode(decoder, slice)?;
        let ecause = decoder.read(decoder.proto_conf.ecause_width_p, slice)?;
        let interrupt = decoder.read_bit(slice)?;
        let thaddr = decoder.read_bit(slice)?;
        let address = read_address(decoder, slice)?;
        let tval = decoder.read(decoder.proto_conf.iaddress_width_p, slice)?;
        Ok(Trap {
            branch,
            ctx,
            ecause,
            interrupt,
            thaddr,
            address,
            tval,
        })
    }
}

/// #### Format 3, sub format 2
/// Informs that the context changed or used as part of other payloads.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Context {
    /// The privilege level of the reported instruction.
    pub privilege: Privilege,
    pub time: u64,
    pub context: u64,
}

impl Decode for Context {
    fn decode(decoder: &mut Decoder, slice: &[u8]) -> Result<Self, DecodeError> {
        Ok(Context {
            privilege: Privilege::decode(decoder, slice)?,
            time: decoder.read(decoder.proto_conf.time_width_p, slice)?,
            context: decoder.read(decoder.proto_conf.context_width_p, slice)?,
        })
    }
}

/// #### Format 3, sub format 3
/// Supporting information for the decoder.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Support {
    pub ienable: bool,
    pub encoder_mode: u64,
    pub qual_status: QualStatus,
    pub ioptions: u64,
    pub denable: bool,
    pub dloss: bool,
    pub doptions: u64,
}

impl Decode for Support {
    fn decode(decoder: &mut Decoder, slice: &[u8]) -> Result<Self, DecodeError> {
        let ienable = decoder.read_bit(slice)?;
        let encoder_mode = decoder.read(decoder.proto_conf.encoder_mode_n, slice)?;
        let qual_status = QualStatus::decode(decoder, slice)?;
        let ioptions = decoder.read(decoder.proto_conf.ioptions_n, slice)?;
        let denable = decoder.read_bit(slice)?;
        let dloss = decoder.read_bit(slice)?;
        let doptions = decoder.read(4, slice)?;
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

#[cfg(test)]
mod tests {
    use crate::decoder::payload::{AddressInfo, Branch, JumpTargetIndex, Privilege, Start};
    use crate::decoder::{Decode, Decoder, DecoderConfiguration};
    use crate::ProtocolConfiguration;

    const DEFAULT_PACKET_BUFFER_LEN: usize = 32;

    #[test]
    fn extension_jti() {
        let protocol_config = ProtocolConfiguration::default();
        let decoder_config = DecoderConfiguration::default();

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
                ..protocol_config
            },
            decoder_config,
        );

        decoder.reset();
        let jti_long = JumpTargetIndex::decode(&mut decoder, &buffer).unwrap();
        assert_eq!(jti_long.index, 768);
        assert_eq!(jti_long.branches, 31);
        assert_eq!(jti_long.branch_map, Some(10));
        let jti_short = JumpTargetIndex::decode(&mut decoder, &buffer).unwrap();
        assert_eq!(jti_short.index, 1023);
        assert_eq!(jti_short.branches, 0);
        assert_eq!(jti_short.branch_map, None);
    }

    #[test]
    fn branch() {
        let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
        buffer[0] = 0b010_00111;
        buffer[1] = 0b0000_1011;
        let mut decoder = Decoder::default();
        decoder.reset();
        let branch = Branch::decode(&mut decoder, &buffer).unwrap();
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

    #[test]
    fn branch_with_zero_branches() {
        let mut buffer = [0; DEFAULT_PACKET_BUFFER_LEN];
        buffer[0] = 0b000_00000;
        buffer[1] = 0b100;
        let mut decoder = Decoder::default();
        decoder.reset();
        let branch_no_addr = Branch::decode(&mut decoder, &buffer).unwrap();
        assert_eq!(branch_no_addr.branches, 0);
        assert_eq!(branch_no_addr.branch_map, 32);
        assert_eq!(branch_no_addr.address, None);
    }

    #[test]
    fn address() {
        let protocol_config = ProtocolConfiguration::default();
        let decoder_config = DecoderConfiguration::default();

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
                ..protocol_config
            },
            decoder_config,
        );
        decoder.reset();
        let addr = AddressInfo::decode(&mut decoder, &buffer).unwrap();
        assert_eq!(addr.address, 4);
        assert!(addr.notify);
        assert!(addr.updiscon);
        // differential address
        let diff_addr = AddressInfo::decode(&mut decoder, &buffer).unwrap();
        assert_eq!(diff_addr.address, 4);
        assert!(!diff_addr.notify);
        assert!(diff_addr.updiscon);
    }

    #[test]
    fn synchronization_start() {
        let protocol_config = ProtocolConfiguration::default();
        let decoder_config = DecoderConfiguration::default();

        let buffer = [255; DEFAULT_PACKET_BUFFER_LEN];
        let mut decoder = Decoder::new(
            ProtocolConfiguration {
                iaddress_width_p: 64,
                iaddress_lsb_p: 0,
                ..protocol_config
            },
            decoder_config,
        );
        decoder.reset();
        let sync_start = Start::decode(&mut decoder, &buffer).unwrap();
        assert!(sync_start.branch);
        assert_eq!(sync_start.ctx.privilege, Privilege::Machine);
        assert_eq!(sync_start.address, u64::MAX);
    }
}
