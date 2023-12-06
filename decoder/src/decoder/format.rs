use crate::decoder::format::Ext::{BranchCount, JumpTargetIndex};
use crate::decoder::{Decode, Decoder};

#[derive(Eq, PartialEq, Debug)]
pub enum Format {
    Ext(Ext),
    Branch,
    Addr,
    Sync(Sync),
}

#[derive(Eq, PartialEq, Debug)]
pub enum Ext {
    BranchCount,
    JumpTargetIndex,
}

impl Decode for Ext {
    fn decode(decoder: &mut Decoder) -> Self {
        match decoder.read_fast_u32(1) {
            0b0 => BranchCount,
            0b1 => JumpTargetIndex,
            _ => panic!(),
        }
    }
}

#[derive(Eq, PartialEq, Debug)]
pub enum Sync {
    Start,
    Trap,
    Context,
    Support,
}

impl Decode for Sync {
    fn decode(decoder: &mut Decoder) -> Self {
        match decoder.read_fast_u32(2) {
            0b00 => Sync::Start,
            0b01 => Sync::Trap,
            0b10 => Sync::Context,
            0b11 => Sync::Support,
            _ => panic!(),
        }
    }
}

impl Decode for Format {
    fn decode(decoder: &mut Decoder) -> Self {
        match decoder.read_fast_u32(2) {
            0b00 => {
                let ext = Ext::decode(decoder);
                Format::Ext(ext)
            }
            0b01 => Format::Branch,
            0b10 => Format::Addr,
            0b11 => {
                let sync = Sync::decode(decoder);
                Format::Sync(sync)
            }
            _ => panic!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::decoder::format::{Ext, Format, Sync};
    use crate::decoder::{Decode, Decoder, DEFAULT_CONFIGURATION};

    #[test_case]
    fn sync() {
        let buffer = [0b1001_0011; 32];
        let mut decoder = Decoder::new(DEFAULT_CONFIGURATION);
        decoder.set_buffer(&buffer);
        assert_eq!(Sync::Trap, Sync::decode(&mut decoder));
        assert_eq!(Sync::Context, Sync::decode(&mut decoder));
        assert_eq!(Sync::Start, Sync::decode(&mut decoder));
        assert_eq!(Sync::Support, Sync::decode(&mut decoder));
    }

    #[test_case]
    fn extension() {
        let buffer = [0b0100_0000; 32];
        let mut decoder = Decoder::new(DEFAULT_CONFIGURATION);
        decoder.set_buffer(&buffer);
        assert_eq!(Ext::BranchCount, Ext::decode(&mut decoder));
        assert_eq!(Ext::JumpTargetIndex, Ext::decode(&mut decoder));
    }

    #[test_case]
    fn format() {
        let mut buffer = [0u8; 32];
        buffer[0] = 0b001_10_01_1;
        buffer[1] = 0b110_00000;
        let mut decoder = Decoder::new(DEFAULT_CONFIGURATION);
        decoder.set_buffer(&buffer);
        assert_eq!(
            Format::Ext(Ext::JumpTargetIndex),
            Format::decode(&mut decoder)
        );
        assert_eq!(Format::Branch, Format::decode(&mut decoder));
        assert_eq!(Format::Addr, Format::decode(&mut decoder));
        assert_eq!(Format::Sync(Sync::Trap), Format::decode(&mut decoder));
    }
}
