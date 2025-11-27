use bounded_integer::BoundedU8;
use std::fmt;

mod anticol_select;
mod atqa;
mod ats;
mod block;
mod crc;
mod pcb;
mod pps;
mod protocol;
mod rats;
mod sak;

use anticol_select::{Cascade, NumberOfValidBits, UidCl};
use atqa::AtqA;
use ats::Ats;
use crc::{append_crc_a, crc_a};
use pps::{PpsParam, PpsResp};
use rats::RatsParam;
use sak::Sak;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeAError {
    InvalidLength,
    UnknownOpcode(u8),
    InvalidCrc((u8, u8)),
    InvalidBcc,
    UnknownSel,
    InvalidPcb,
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
    Pps(PpsResp),
    Block(Block),
}

#[derive(Debug)]
pub enum Command {
    ReqA,
    WupA,
    AntiCollision((Cascade, NumberOfValidBits)),
    Select(Cascade),
    HltA,
    Rats(RatsParam),
    Pps(PpsParam),
    IBlock(Block),
    RBlock(Block),
    SBlock(Block),
}

impl Command {
    pub fn frame(&self) -> Frame {
        match self {
            Command::ReqA | Command::WupA => Frame::Short,
            Command::HltA
            | Command::Select(_)
            | Command::Rats(_)
            | Command::Pps(_)
            | Command::IBlock(_)
            | Command::RBlock(_)
            | Command::SBlock(_) => Frame::Standard,
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
            Command::Pps(param) => {
                append_crc_a(&[0xd0 + u8::from(&param.cid), 0x11, u8::from(param)])
            }
            Command::IBlock(block) | Command::RBlock(block) | Command::SBlock(block) => {
                append_crc_a(&block.to_vec())
            }
        }
    }

    pub fn parse_answer(&self, raw: &[u8]) -> Result<Answer, TypeAError> {
        match self {
            Command::ReqA | Command::WupA => Ok(Answer::AtqA(AtqA::try_from(raw)?)),
            Command::AntiCollision(_) => Ok(Answer::UidCl(UidCl::try_from(raw)?)),
            Command::Select(_) => Ok(Answer::Sak(Sak::try_from(raw)?)),
            Command::HltA => unreachable!("HLTA should be answered"),
            Command::Rats(_) => Ok(Answer::Ats(Ats::try_from(raw)?)),
            Command::Pps(_) => Ok(Answer::Pps(PpsResp::try_from(raw)?)),
            Command::IBlock(_) | Command::RBlock(_) | Command::SBlock(_) => {
                Ok(Answer::Block(Block::try_from(raw)?))
            }
        }
    }
}

impl TryFrom<&[u8]> for Command {
    type Error = TypeAError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match *value {
            [0x26] => Ok(Command::ReqA),
            [0x52] => Ok(Command::WupA),
            [0x50, 0x00, crc1, crc2] => {
                let good = crc_a(&[0x50, 0x00]);
                if good == (crc1, crc2) || (0, 0) == (crc1, crc2) {
                    Ok(Command::HltA)
                } else {
                    Err(TypeAError::InvalidCrc(good))
                }
            }
            [0xe0, param, crc1, crc2] => {
                let good = crc_a(&[0xe0, param]);
                if good == (crc1, crc2) || (0, 0) == (crc1, crc2) {
                    Ok(Command::Rats(RatsParam::try_from(param)?))
                } else {
                    Err(TypeAError::InvalidCrc(good))
                }
            }
            [sel, nvb] if Cascade::check_sel(sel) => {
                let cascade = Cascade::try_from(sel, &[0, 0, 0, 0, 0])
                    .map_err(|_| TypeAError::UnknownOpcode(sel))?;
                let nvb = NumberOfValidBits::try_from(nvb)?;
                Ok(Command::AntiCollision((cascade, nvb)))
            }
            [sel, nvb, uid0, uid1, uid2, uid3, bcc, crc1, crc2] if Cascade::check_sel(sel) => {
                let good = crc_a(&[sel, nvb, uid0, uid1, uid2, uid3, bcc]);
                if good == (crc1, crc2) || (0, 0) == (crc1, crc2) {
                    let cascade = Cascade::try_from(sel, &[uid0, uid1, uid2, uid3, bcc])
                        .map_err(|_| TypeAError::UnknownOpcode(sel))?;
                    let nvb = NumberOfValidBits::try_from(nvb)?;
                    if nvb.has_40_data_bits() {
                        Ok(Command::Select(cascade))
                    } else {
                        Ok(Command::AntiCollision((cascade, nvb)))
                    }
                } else {
                    Err(TypeAError::InvalidCrc(good))
                }
            }
            _ => {
                if value.is_empty() {
                    Err(TypeAError::InvalidLength)
                } else if value[0] & 0xF0 == 0xD0 {
                    Ok(Command::Pps(PpsParam::try_from(value)?))
                } else {
                    // Try to parse as a block
                    match Block::try_from(value) {
                        Ok(block) => match block.block_type() {
                            BlockType::IBlock => Ok(Command::IBlock(block)),
                            BlockType::RBlock => Ok(Command::RBlock(block)),
                            BlockType::SBlock => Ok(Command::SBlock(block)),
                        },
                        Err(_) => Err(TypeAError::UnknownOpcode(value[0])),
                    }
                }
            }
        }
    }
}

// Re-export block-related types
pub use block::{Block, Cid as BlockCid};
pub use pcb::{BlockType, Pcb, PcbFlags, RBlockSubtype, SBlockSubtype};
pub use protocol::{BlockChain, ProtocolHandler, ProtocolState};

pub struct Cid(BoundedU8<0, 14>);

impl fmt::Debug for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.get())
    }
}
