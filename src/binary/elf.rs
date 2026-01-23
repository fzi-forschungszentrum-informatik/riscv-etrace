// Copyright (C) 2025 FZI Forschungszentrum Informatik
// SPDX-License-Identifier: Apache-2.0
//! ELF related utilities

use core::borrow::Borrow;
use core::fmt;

use elf::ElfBytes;
use elf::endian::EndianParse;

use crate::instruction::{Instruction, base, info};

use super::{Binary, error};

/// Static ELF [`Binary`]
///
/// This [`Binary`] retrieves [`Instruction`]s from executable `LOAD` segments
/// found in [`ElfBytes`] based on virtual address mapping. Neither
/// decompression nor dynamic linking are supported.
#[derive(Copy, Clone)]
pub struct Elf<'d, E, P, D = base::Set>
where
    E: Borrow<ElfBytes<'d, P>>,
    P: EndianParse,
{
    elf: E,
    last_segment: (u64, &'d [u8]),
    base: D,
    phantom: core::marker::PhantomData<P>,
}

impl<'d, E, P, D> Elf<'d, E, P, D>
where
    E: Borrow<ElfBytes<'d, P>>,
    P: EndianParse,
    D: info::MakeDecode,
{
    /// Create a new ELF [`Binary`]
    pub fn new(elf: E) -> Result<Self, Error> {
        use elf::abi;

        let hdr = &elf.borrow().ehdr;
        if hdr.e_machine != abi::EM_RISCV {
            Err(Error::UnsupportedArchitecture)
        } else if !hdr.endianness.is_little() {
            Err(Error::UnsupportedEndianess)
        } else {
            let base = match hdr.class {
                elf::file::Class::ELF32 => info::MakeDecode::rv32i_full(),
                elf::file::Class::ELF64 => info::MakeDecode::rv64i_full(),
            };

            Ok(Self {
                elf,
                last_segment: (u64::MAX, &[]),
                base,
                phantom: Default::default(),
            })
        }
    }

    /// Retrieve the inner [`ElfBytes`]
    pub fn inner(&self) -> &ElfBytes<'d, P> {
        self.elf.borrow()
    }

    /// Retrieve the [`base::Set`] of the instruction in this ELF
    pub fn base_set(&self) -> &D {
        &self.base
    }
}

impl<'d, E, P, D, I> Binary<I> for Elf<'d, E, P, D>
where
    E: Borrow<ElfBytes<'d, P>>,
    P: EndianParse,
    I: info::Info,
    D: info::Decode<I>,
{
    type Error = Error;

    fn get_insn(&mut self, address: u64) -> Result<Instruction<I>, Self::Error> {
        // Iterator over all relevant segments' offset and data
        let segments = self
            .elf
            .borrow()
            .segments()
            .into_iter()
            .flat_map(|s| s.iter())
            .filter(|s| s.p_type == elf::abi::PT_LOAD && s.p_flags & elf::abi::PF_X != 0)
            .map(|s| {
                self.elf
                    .borrow()
                    .segment_data(&s)
                    .map(|d| (s.p_vaddr, d))
                    .map_err(Error::CouldNotRetrieveData)
            });

        // Find the relevant instruction data, starting with the last segment
        // used since that's most likely to be the relevant one. We accept that
        // we may fail if we could not retrieve data for a segment known to not
        // contain the address.
        let (insn_data, segment) = core::iter::once(Ok(self.last_segment))
            .chain(segments)
            .map(|s| {
                let (base, data) = s?;
                let Some(offset) = address.checked_sub(base) else {
                    // `address` < segment start
                    return Ok(None);
                };
                let offset = offset.try_into().map_err(Error::ExceededHostUSize)?;
                let res = data
                    .split_at_checked(offset)
                    .filter(|(_, insn_data)| !insn_data.is_empty())
                    .map(|(_, insn_data)| (insn_data, (base, data)));
                Ok(res)
            })
            .find_map(Result::transpose)
            .ok_or(Error::NoSegmentFound)??;

        self.last_segment = segment;
        Instruction::extract(insn_data, &self.base)
            .map(|(i, _)| i)
            .ok_or(Error::InvalidInstruction)
    }
}

/// ELF specific error type
#[derive(Debug)]
pub enum Error {
    /// No segment was found containing the address
    NoSegmentFound,
    /// The data for a segment could not be retrieved
    CouldNotRetrieveData(elf::parse::ParseError),
    /// Could not use an address or offset because it is too big for the host
    ExceededHostUSize(core::num::TryFromIntError),
    /// An [`Instruction`] could not be extracted from the data
    InvalidInstruction,
    /// The ELF file is not an RV32 ELF file
    UnsupportedArchitecture,
    /// The ELF file is not little endian
    UnsupportedEndianess,
}

impl error::Miss for Error {
    fn miss(_: u64) -> Self {
        Self::NoSegmentFound
    }
}

impl error::MaybeMiss for Error {
    fn is_miss(&self) -> bool {
        matches!(self, Self::NoSegmentFound)
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::CouldNotRetrieveData(e) => Some(e),
            Self::ExceededHostUSize(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSegmentFound => write!(f, "Could not find segment for address"),
            Self::CouldNotRetrieveData(_) => write!(f, "Could not retrieve data for segment"),
            Self::ExceededHostUSize(_) => write!(
                f,
                "An offset exceeds what can be represented with host native addresses"
            ),
            Self::InvalidInstruction => write!(f, "No valid instruction at address"),
            Self::UnsupportedArchitecture => write!(f, "The target architecture is not supported"),
            Self::UnsupportedEndianess => write!(f, "The target is not little endian"),
        }
    }
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::NoSegmentFound, Self::NoSegmentFound) => true,
            (Self::CouldNotRetrieveData(_), Self::CouldNotRetrieveData(_)) => true,
            (Self::ExceededHostUSize(l), Self::ExceededHostUSize(r)) => l == r,
            (Self::InvalidInstruction, Self::InvalidInstruction) => true,
            (Self::UnsupportedArchitecture, Self::UnsupportedArchitecture) => true,
            (Self::UnsupportedEndianess, Self::UnsupportedEndianess) => true,
            _ => false,
        }
    }
}
