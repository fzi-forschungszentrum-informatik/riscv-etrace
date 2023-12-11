use super::{BranchFmt, Decode, Decoder};

pub struct ContextPart {
    pub privilege: u64,
    #[cfg(feature = "time")]
    pub time: u64,
    #[cfg(feature = "context")]
    pub context: u64,
}

impl Decode for ContextPart {
    fn decode(decoder: &mut Decoder) -> Self {
        ContextPart {
            privilege: decoder.read_u64(decoder.conf.privilege_width_p),
            #[cfg(feature = "time")]
            time: decoder.read_u64(decoder.conf.time_width_p),
            #[cfg(feature = "context")]
            context: decoder.read_u64(decoder.conf.context_width_p),
        }
    }
}

pub struct AddressPart {
    pub address: u64,
    pub notify: bool,
    pub updiscon: bool,
}

impl Decode for AddressPart {
    fn decode(decoder: &mut Decoder) -> Self {
        AddressPart {
            address: decoder.read_address(),
            notify: decoder.read_bool_bit(),
            updiscon: decoder.read_bool_bit(),
        }
    }
}

#[cfg(feature = "IR")]
pub struct IRPayload {
    pub irreport: usize,
    pub irdepth: usize,
}

#[cfg(feature = "IR")]
impl Decode for IRPayload {
    fn decode(decoder: &mut Decoder) -> Self {
        unimplemented!()
    }
}

pub struct BranchPart {
    pub branches: usize,
    pub branch_map: u32,
}

impl Decode for BranchPart {
    fn decode(decoder: &mut Decoder) -> Self {
        let branches = match decoder.read_fast_u32(5) {
            0 => 31,
            1 => 1,
            2..=3 => 3,
            4..=7 => 7,
            8..=15 => 15,
            16..=31 => 31,
            _ => panic!(),
        };
        BranchPart {
            branches,
            branch_map: decoder.read_u64(branches).try_into().unwrap(),
        }
    }
}

pub struct BranchCountPart {
    pub branch_count: u32,
    pub branch_fmt: BranchFmt,
}

impl Decode for BranchCountPart {
    fn decode(decoder: &mut Decoder) -> Self {
        let branch_count = decoder.read_fast_u32(32) - 31;
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

impl Decode for ShortBranchPart {
    fn decode(decoder: &mut Decoder) -> Self {
        let branches = match decoder.read_fast_u32(5) {
            0 => 0,
            1 => 1,
            2..=3 => 3,
            4..=7 => 7,
            8..=15 => 15,
            16..=31 => 31,
            _ => panic!(),
        };
        ShortBranchPart {
            branches,
            branch_map: if branches == 0 {
                None
            } else {
                Some(decoder.read_u64(branches).try_into().unwrap())
            },
        }
    }
}
