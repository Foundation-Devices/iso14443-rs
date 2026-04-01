use bounded_integer::BoundedU8;
use core::fmt;

pub mod activation;
mod anticol_select;
mod atqa;
mod ats;
mod block;
pub(crate) mod crc;
mod pcb;
pub mod pcd;
mod pps;
mod protocol;
mod rats;
mod sak;
pub mod vec;

use anticol_select::{Cascade, UidCl};
pub use anticol_select::{NumberOfValidBits, SEL_CL1, SEL_CL2, SEL_CL3};
pub use atqa::AtqA;
pub use ats::Ats;
use crc::{append_crc_a, crc_a};
use pps::{PpsParam, PpsResp};
pub use rats::RatsParam;
pub use sak::Sak;
use vec::{FrameVec, VecExt};

/// Trait for ISO14443 Type A PCD (reader) transceiver hardware.
///
/// Implementors handle the physical layer and translate
/// the ISO14443 frame types into hardware-specific commands.
/// A future `PiccTransceiver` trait can model the card emulation side.
pub trait PcdTransceiver {
    type Error;

    /// Send data using the specified frame format, return protocol response
    /// bytes. Hardware-specific metadata must be stripped by the
    /// implementation.
    fn transceive(&mut self, frame: &Frame) -> Result<FrameVec, Self::Error>;

    /// Probe for hardware-accelerated CRC_A support and enable it.
    ///
    /// This is a one-time capability check, typically called early during
    /// activation. The result determines the CRC strategy for the entire
    /// session:
    ///
    /// - `Ok(())`: the chip handles CRC_A in hardware. From this point on,
    ///   callers send frame data **without** CRC_A — the transceiver appends
    ///   it on TX and validates/strips it on RX.
    /// - `Err(_)`: the chip does not support hardware CRC. Callers must
    ///   compute and append CRC_A in software (via [`crc::append_crc_a`]) and
    ///   validate it on received frames.
    fn enable_hw_crc(&mut self) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeAError {
    InvalidLength,
    UnknownOpcode(u8),
    InvalidCrc((u8, u8)),
    InvalidBcc,
    UnknownSel,
    InvalidPcb,
    BufferFull,
    Other,
}

/// 6.1.5 Frame formats
///
/// Each variant carries the data to be transmitted.
pub enum Frame {
    /// Short frame: 7 significant bits, no CRC (REQA, WUPA).
    Short(FrameVec),
    /// Standard frame: full bytes with CRC (SELECT, RATS, HLTA, blocks).
    Standard(FrameVec),
    /// Bit-oriented frame: full bytes, no CRC (anticollision).
    BitOriented(FrameVec),
}

impl Frame {
    /// Borrow the frame data.
    pub fn data(&self) -> &[u8] {
        match self {
            Frame::Short(d) | Frame::Standard(d) | Frame::BitOriented(d) => d,
        }
    }
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
    /// Build a [`Frame`] with the command data and correct frame format.
    ///
    /// Standard frames include CRC_A computed in software.
    pub fn to_frame(&self) -> Result<Frame, TypeAError> {
        match self {
            Command::ReqA | Command::WupA => Ok(Frame::Short(self.to_vec()?)),
            Command::AntiCollision(_) => Ok(Frame::BitOriented(self.to_vec()?)),
            _ => Ok(Frame::Standard(self.to_vec()?)),
        }
    }

    pub fn to_vec(&self) -> Result<FrameVec, TypeAError> {
        match self {
            Command::ReqA => {
                let mut v = FrameVec::new();
                v.try_push(0x26)?;
                Ok(v)
            }
            Command::WupA => {
                let mut v = FrameVec::new();
                v.try_push(0x52)?;
                Ok(v)
            }
            Command::AntiCollision((cascade, nvb)) => cascade.raw(u8::from(nvb)),
            Command::Select(cascade) => append_crc_a(cascade.raw(0x70)?.as_slice()),
            Command::HltA => append_crc_a(&[0x50, 0x00]),
            Command::Rats(param) => append_crc_a(&[0xe0, u8::from(param)]),
            Command::Pps(param) => {
                append_crc_a(&[0xd0 + u8::from(&param.cid), 0x11, u8::from(param)])
            }
            Command::IBlock(block) | Command::RBlock(block) | Command::SBlock(block) => {
                append_crc_a(&block.to_vec()?)
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
pub use ats::Fsci;
pub use block::Block;
pub use pcb::{BlockType, Pcb, PcbFlags, RBlockSubtype, SBlockSubtype};
pub use pcd::{Pcd, PcdError};
pub use pps::Dxi;
pub use protocol::{Action, ProtocolHandler};
pub use rats::Fsdi;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Cid(pub BoundedU8<0, 14>);

impl Cid {
    pub fn new(value: u8) -> Option<Self> {
        if value <= 14 {
            Some(Self(BoundedU8::new(value).unwrap()))
        } else {
            None
        }
    }

    pub fn value(&self) -> u8 {
        self.0.get()
    }
}

impl fmt::Debug for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.get())
    }
}
