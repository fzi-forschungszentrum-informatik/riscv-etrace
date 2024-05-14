use crate::decoder::format::Ext::{BranchCount, JumpTargetIndex};
use crate::decoder::{Decode, DecodeError, Decoder};

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
    fn decode(decoder: &mut Decoder, slice: &[u8]) -> Result<Self, DecodeError> {
        Ok(match decoder.read_bit(slice)? {
            false => BranchCount,
            true => JumpTargetIndex,
        })
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
    fn decode(decoder: &mut Decoder, slice: &[u8]) -> Result<Self, DecodeError> {
        Ok(match decoder.read(2, slice)? {
            0b00 => Sync::Start,
            0b01 => Sync::Trap,
            0b10 => Sync::Context,
            0b11 => Sync::Support,
            _ => unreachable!(),
        })
    }
}

impl Decode for Format {
    fn decode(decoder: &mut Decoder, slice: &[u8]) -> Result<Self, DecodeError> {
        Ok(match decoder.read(2, slice)? {
            0b00 => {
                let ext = Ext::decode(decoder, slice)?;
                Format::Ext(ext)
            }
            0b01 => Format::Branch,
            0b10 => Format::Addr,
            0b11 => {
                let sync = Sync::decode(decoder, slice)?;
                Format::Sync(sync)
            }
            _ => unreachable!(),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::decoder::format::{Ext, Format, Sync};
    use crate::decoder::{Decode, Decoder};

    #[test_case]
    fn sync() {
        let buffer = [0b10_01_00_11u8; 32];
        let mut decoder = Decoder::default();
        decoder.reset();
        assert_eq!(Sync::decode(&mut decoder, &buffer).unwrap(), Sync::Support);
        assert_eq!(Sync::decode(&mut decoder, &buffer).unwrap(), Sync::Start);
        assert_eq!(Sync::decode(&mut decoder, &buffer).unwrap(), Sync::Trap);
        assert_eq!(Sync::decode(&mut decoder, &buffer).unwrap(), Sync::Context);
    }

    #[test_case]
    fn extension() {
        let buffer = [0b0010u8; 32];
        let mut decoder = Decoder::default();
        decoder.reset();
        assert_eq!(Ext::decode(&mut decoder, &buffer).unwrap(), Ext::BranchCount);
        assert_eq!(Ext::decode(&mut decoder, &buffer).unwrap(), Ext::JumpTargetIndex);
    }

    #[test_case]
    fn format() {
        let mut buffer = [0u8; 32];
        buffer[0] = 0b1_10_01_100;
        buffer[1] = 0b00000_011;
        let mut decoder = Decoder::default();
        decoder.reset();
        assert_eq!(
            Format::decode(&mut decoder, &buffer).unwrap(),
            Format::Ext(Ext::JumpTargetIndex),
        );
        assert_eq!(Format::decode(&mut decoder, &buffer).unwrap(), Format::Branch);
        assert_eq!(Format::decode(&mut decoder, &buffer).unwrap(), Format::Addr);
        assert_eq!(
            Format::decode(&mut decoder, &buffer).unwrap(),
            Format::Sync(Sync::Trap)
        );
    }
}
