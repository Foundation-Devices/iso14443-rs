mod anticol_select;
mod atqa;
mod ats;
mod crc;
mod rats;
mod sak;

use anticol_select::{Cascade, NumberOfValidBits, UidCl};
use atqa::AtqA;
use ats::Ats;
use crc::{append_crc_a, crc_a};
use rats::RatsParam;
use sak::Sak;

#[derive(Debug)]
pub enum TypeAError {
    InvalidLength,
    UnknownOpcode,
    InvalidCrc,
    InvalidBcc,
    UnknownSel,
    Other,
}

/// 6.1.5 Frame formats
pub enum Frame {
    Short,
    Standard,
    BitOriented,
}

#[derive(Debug)]
pub enum Answer {
    AtqA(AtqA),
    UidCl(UidCl),
    Sak(Sak),
    Ats(Ats),
}

#[derive(Debug)]
pub enum Command {
    ReqA,
    WupA,
    AntiCollision((Cascade, NumberOfValidBits)),
    Select(Cascade),
    HltA,
    Rats(RatsParam),
}

impl Command {
    pub fn frame(&self) -> Frame {
        match self {
            Command::ReqA | Command::WupA => Frame::Short,
            Command::HltA | Command::Select(_) | Command::Rats(_) => Frame::Standard,
            Command::AntiCollision(_) => Frame::BitOriented,
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Command::ReqA => vec![0x26],
            Command::WupA => vec![0x52],
            Command::AntiCollision((cascade, nvb)) => cascade.raw(u8::from(nvb)),
            Command::Select(cascade) => append_crc_a(cascade.raw(0x70).as_slice()),
            Command::HltA => append_crc_a(&[0x50, 0x00]),
            Command::Rats(param) => append_crc_a(&[0xe0, u8::from(param)]),
        }
    }

    pub fn parse_answer(&self, raw: &[u8]) -> Result<Answer, TypeAError> {
        match self {
            Command::ReqA | Command::WupA => Ok(Answer::AtqA(AtqA::try_from(raw)?)),
            Command::AntiCollision(_) => Ok(Answer::UidCl(UidCl::try_from(raw)?)),
            Command::Select(_) => Ok(Answer::Sak(Sak::try_from(raw)?)),
            Command::HltA => unreachable!("HLTA should be answered"),
            Command::Rats(_) => Ok(Answer::Ats(Ats::try_from(raw)?)),
        }
    }
}

impl TryFrom<&[u8]> for Command {
    type Error = TypeAError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match value {
            &[0x26] => Ok(Command::ReqA),
            &[0x52] => Ok(Command::WupA),
            &[0x50, 0x00, crc1, crc2] => {
                if crc_a(&[0x50, 0x00]) == (crc1, crc2) {
                    Ok(Command::HltA)
                } else {
                    Err(TypeAError::InvalidCrc)
                }
            }
            &[0xe0, param, crc1, crc2] => {
                if crc_a(&[0xe0, param]) == (crc1, crc2) {
                    Ok(Command::Rats(RatsParam::try_from(param)?))
                } else {
                    Err(TypeAError::InvalidCrc)
                }
            }
            &[sel, nvb] if Cascade::check_sel(sel) => {
                let cascade = Cascade::try_from(sel, &[0, 0, 0, 0, 0])
                    .map_err(|_| TypeAError::UnknownOpcode)?;
                let nvb = NumberOfValidBits::try_from(nvb)?;
                Ok(Command::AntiCollision((cascade, nvb)))
            }
            &[sel, nvb, uid0, uid1, uid2, uid3, bcc, crc1, crc2] if Cascade::check_sel(sel) => {
                if crc_a(&[sel, nvb, uid0, uid1, uid2, uid3, bcc]) == (crc1, crc2) {
                    let cascade = Cascade::try_from(sel, &[uid0, uid1, uid2, uid3, bcc])
                        .map_err(|_| TypeAError::UnknownOpcode)?;
                    let nvb = NumberOfValidBits::try_from(nvb)?;
                    if nvb.has_40_data_bits() {
                        Ok(Command::Select(cascade))
                    } else {
                        Ok(Command::AntiCollision((cascade, nvb)))
                    }
                } else {
                    Err(TypeAError::InvalidCrc)
                }
            }
            _ => {
                if value.len() < 1 {
                    Err(TypeAError::InvalidLength)
                } else {
                    Err(TypeAError::UnknownOpcode)
                }
            }
        }
    }
}
