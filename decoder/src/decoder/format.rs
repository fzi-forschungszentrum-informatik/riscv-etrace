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

impl<const PACKET_BUFFER_LEN: usize> Decode<PACKET_BUFFER_LEN> for Ext {
    fn decode(decoder: &mut Decoder<PACKET_BUFFER_LEN>) -> Result<Self, DecodeError> {
        Ok(match decoder.read_bit()? {
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

impl<const PACKET_BUFFER_LEN: usize> Decode<PACKET_BUFFER_LEN> for Sync {
    fn decode(decoder: &mut Decoder<PACKET_BUFFER_LEN>) -> Result<Self, DecodeError> {
        Ok(match decoder.read(2)? {
            0b00 => Sync::Start,
            0b01 => Sync::Trap,
            0b10 => Sync::Context,
            0b11 => Sync::Support,
            _ => unreachable!(),
        })
    }
}

impl<const PACKET_BUFFER_LEN: usize> Decode<PACKET_BUFFER_LEN> for Format {
    fn decode(decoder: &mut Decoder<PACKET_BUFFER_LEN>) -> Result<Self, DecodeError> {
        Ok(match decoder.read(2)? {
            0b00 => {
                let ext = Ext::decode(decoder)?;
                Format::Ext(ext)
            }
            0b01 => Format::Branch,
            0b10 => Format::Addr,
            0b11 => {
                let sync = Sync::decode(decoder)?;
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
        decoder.set_buffer(buffer);
        assert_eq!(Sync::decode(&mut decoder).unwrap(), Sync::Support);
        assert_eq!(Sync::decode(&mut decoder).unwrap(), Sync::Start);
        assert_eq!(Sync::decode(&mut decoder).unwrap(), Sync::Trap);
        assert_eq!(Sync::decode(&mut decoder).unwrap(), Sync::Context);
    }

    #[test_case]
    fn extension() {
        let buffer = [0b0010u8; 32];
        let mut decoder = Decoder::default();
        decoder.set_buffer(buffer);
        assert_eq!(Ext::decode(&mut decoder).unwrap(), Ext::BranchCount);
        assert_eq!(Ext::decode(&mut decoder).unwrap(), Ext::JumpTargetIndex);
    }

    #[test_case]
    fn format() {
        let mut buffer = [0u8; 32];
        buffer[0] = 0b1_10_01_100;
        buffer[1] = 0b00000_011;
        let mut decoder = Decoder::default();
        decoder.set_buffer(buffer);
        assert_eq!(
            Format::decode(&mut decoder).unwrap(),
            Format::Ext(Ext::JumpTargetIndex),
        );
        assert_eq!(Format::decode(&mut decoder).unwrap(), Format::Branch);
        assert_eq!(Format::decode(&mut decoder).unwrap(), Format::Addr);
        assert_eq!(
            Format::decode(&mut decoder).unwrap(),
            Format::Sync(Sync::Trap)
        );
    }
}
