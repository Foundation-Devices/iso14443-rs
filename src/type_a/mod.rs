//! ISO/IEC 14443 Type A.
//!
//! ## Parsing and CRC_A
//!
//! Standard frames carry a two-byte CRC_A epilogue, and each type has two
//! ways in:
//!
//! - `TryFrom<&[u8]>` takes raw wire bytes, CRC included, and rejects any
//!   frame whose CRC_A does not match the data it covers.
//! - `from_crc_verified` takes the data of a frame whose CRC_A a trusted
//!   transceiver has already validated and stripped — the hardware-CRC path
//!   of [`PcdTransceiver`] and [`PiccTransceiver`]. The caller vouches for
//!   the integrity of those bytes; nothing about them is re-checked.
//!
//! Short frames (REQA/WUPA) and bit-oriented anticollision frames carry no
//! CRC_A at all, so both entry points parse them identically.

use bounded_integer::BoundedU8;
use core::fmt;

pub mod activation;
mod anticol_select;
mod atqa;
mod ats;
mod block;
pub(crate) mod crc;
pub mod limits;
mod pcb;
pub mod pcd;
pub mod picc;
mod pps;
mod protocol;
mod rats;
mod sak;
pub mod vec;

use anticol_select::{Cascade, UidCl};
pub use anticol_select::{NumberOfValidBits, SEL_CL1, SEL_CL2, SEL_CL3};
pub use atqa::{AtqA, BitFrameAntiCollision, UidSize};
pub use ats::Ats;
use crc::{append_crc_a, split_crc_a};
use pps::{PpsParam, PpsResp};
pub use rats::RatsParam;
pub use sak::Sak;
use vec::{FrameVec, VecExt};

/// Trait for ISO14443 Type A PCD (reader) transceiver hardware.
///
/// Implementors handle the physical layer and translate
/// the ISO14443 frame types into hardware-specific commands.
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
    ///   it on TX and validates/strips it on RX. Returning `Ok(())` is a
    ///   promise that received frames really were checked: their bytes are
    ///   parsed with the `from_crc_verified` constructors, which perform no
    ///   integrity check of their own.
    /// - `Err(_)`: the chip does not support hardware CRC. Received frames
    ///   still carry their CRC_A and are parsed with `TryFrom<&[u8]>`, which
    ///   checks it.
    fn try_enable_hw_crc(&mut self) -> Result<(), Self::Error>;
}

/// Trait for ISO14443 Type A PICC (card emulation) transceiver hardware.
///
/// Unlike [`PcdTransceiver`] which has an atomic `transceive()`, the PICC
/// splits receive and send because it needs to process the incoming command
/// and compute its response between the two calls.
pub trait PiccTransceiver {
    type Error;

    /// Wait for and return the next frame from the PCD.
    fn receive(&mut self) -> Result<FrameVec, Self::Error>;

    /// Send a response frame back to the PCD.
    fn send(&mut self, frame: &Frame) -> Result<(), Self::Error>;

    /// Probe for hardware-accelerated CRC_A support and enable it.
    ///
    /// Same semantics as [`PcdTransceiver::try_enable_hw_crc`].
    fn try_enable_hw_crc(&mut self) -> Result<(), Self::Error>;
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
    /// A peer ran past one of the per-exchange work limits.
    LimitExceeded(Limit),
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
                block.to_vec()
            }
        }
    }

    /// Parse a command whose CRC_A a trusted transceiver has already
    /// validated and stripped.
    ///
    /// Short frames (REQA/WUPA) and bit-oriented anticollision frames carry
    /// no CRC_A at all, so they parse the same either way.
    ///
    /// Use [`Command::try_from`] for bytes that came off the air unverified.
    pub fn from_crc_verified(data: &[u8]) -> Result<Self, TypeAError> {
        match *data {
            [0x26] => Ok(Command::ReqA),
            [0x52] => Ok(Command::WupA),
            [sel, nvb] if Cascade::check_sel(sel) => {
                let cascade = Cascade::try_from(sel, &[0, 0, 0, 0, 0])
                    .map_err(|_| TypeAError::UnknownOpcode(sel))?;
                let nvb = NumberOfValidBits::try_from(nvb)?;
                Ok(Command::AntiCollision((cascade, nvb)))
            }
            _ => Self::parse_standard(data),
        }
    }

    /// Parse the data of a standard (CRC-carrying) frame, CRC excluded.
    fn parse_standard(data: &[u8]) -> Result<Self, TypeAError> {
        match *data {
            [0x50, 0x00] => Ok(Command::HltA),
            [0xe0, param] => Ok(Command::Rats(RatsParam::try_from(param)?)),
            [sel, nvb, uid0, uid1, uid2, uid3, bcc] if Cascade::check_sel(sel) => {
                let cascade = Cascade::try_from(sel, &[uid0, uid1, uid2, uid3, bcc])
                    .map_err(|_| TypeAError::UnknownOpcode(sel))?;
                let nvb = NumberOfValidBits::try_from(nvb)?;
                if nvb.has_40_data_bits() {
                    Ok(Command::Select(cascade))
                } else {
                    Ok(Command::AntiCollision((cascade, nvb)))
                }
            }
            _ => {
                if data.is_empty() {
                    Err(TypeAError::InvalidLength)
                } else if data[0] & 0xF0 == 0xD0 {
                    Ok(Command::Pps(PpsParam::from_crc_verified(data)?))
                } else {
                    // Try to parse as a block
                    match Block::from_crc_verified(data) {
                        Ok(block) => match block.block_type() {
                            BlockType::IBlock => Ok(Command::IBlock(block)),
                            BlockType::RBlock => Ok(Command::RBlock(block)),
                            BlockType::SBlock => Ok(Command::SBlock(block)),
                        },
                        Err(_) => Err(TypeAError::UnknownOpcode(data[0])),
                    }
                }
            }
        }
    }

    /// Parse the PICC's answer to this command from wire bytes, CRC_A
    /// epilogue included wherever the frame format carries one.
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

    /// Parse the PICC's answer to this command from bytes whose CRC_A a
    /// trusted transceiver has already validated and stripped.
    ///
    /// ATQA and the anticollision UID answers carry no CRC_A, so they parse
    /// the same either way.
    pub fn parse_answer_crc_verified(&self, raw: &[u8]) -> Result<Answer, TypeAError> {
        match self {
            Command::ReqA | Command::WupA => Ok(Answer::AtqA(AtqA::try_from(raw)?)),
            Command::AntiCollision(_) => Ok(Answer::UidCl(UidCl::try_from(raw)?)),
            Command::Select(_) => Ok(Answer::Sak(Sak::from_crc_verified(raw)?)),
            Command::HltA => unreachable!("HLTA should be answered"),
            Command::Rats(_) => Ok(Answer::Ats(Ats::from_crc_verified(raw)?)),
            Command::Pps(_) => Ok(Answer::Pps(PpsResp::from_crc_verified(raw)?)),
            Command::IBlock(_) | Command::RBlock(_) | Command::SBlock(_) => {
                Ok(Answer::Block(Block::from_crc_verified(raw)?))
            }
        }
    }
}

impl TryFrom<&[u8]> for Command {
    type Error = TypeAError;

    /// Parse a command off the wire. Standard frames must carry the CRC_A
    /// calculated over their data; short and bit-oriented frames carry none.
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match *value {
            [0x26] => Ok(Command::ReqA),
            [0x52] => Ok(Command::WupA),
            [sel, nvb] if Cascade::check_sel(sel) => {
                let cascade = Cascade::try_from(sel, &[0, 0, 0, 0, 0])
                    .map_err(|_| TypeAError::UnknownOpcode(sel))?;
                let nvb = NumberOfValidBits::try_from(nvb)?;
                Ok(Command::AntiCollision((cascade, nvb)))
            }
            _ => Self::parse_standard(split_crc_a(value)?),
        }
    }
}

// Re-export block-related types
pub use ats::{Fsci, Fwi, Sfgi, Ta, Tb, Tc};
pub use block::Block;
pub use limits::{Limit, Limits};
pub use pcb::{BlockType, Pcb, PcbFlags, RBlockSubtype, SBlockSubtype};
pub use pcd::{Pcd, PcdError};
pub use picc::{Picc, PiccConfig, PiccError, Uid};
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

#[cfg(test)]
mod crc_tests {
    //! The CRC_A of a standard frame is checked, never assumed: parsers of
    //! wire bytes accept `00 00` only when it is the calculated CRC, and
    //! CRC-free bytes go through the `from_crc_verified` constructors.

    use super::crc::crc_a;
    use super::*;

    /// A frame carrying the all-zero CRC sentinel instead of its CRC_A.
    fn zero_crc(data: &[u8]) -> FrameVec {
        let mut v = FrameVec::new();
        v.try_extend(data).unwrap();
        v.try_push(0).unwrap();
        v.try_push(0).unwrap();
        v
    }

    /// A frame whose CRC_A is off by one bit.
    fn bad_crc(data: &[u8]) -> FrameVec {
        let mut v = append_crc_a(data).unwrap();
        let last = v.len() - 1;
        v[last] ^= 0x01;
        v
    }

    fn is_invalid_crc<T: core::fmt::Debug>(result: Result<T, TypeAError>) -> bool {
        matches!(result, Err(TypeAError::InvalidCrc(_)))
    }

    #[test]
    fn command_hlta() {
        let data = [0x50, 0x00];
        assert!(matches!(
            Command::try_from(append_crc_a(&data).unwrap().as_slice()),
            Ok(Command::HltA)
        ));
        assert!(is_invalid_crc(Command::try_from(
            zero_crc(&data).as_slice()
        )));
        assert!(is_invalid_crc(Command::try_from(bad_crc(&data).as_slice())));
        assert!(matches!(
            Command::from_crc_verified(&data),
            Ok(Command::HltA)
        ));
    }

    #[test]
    fn command_rats() {
        let data = [0xe0, 0x50];
        assert!(matches!(
            Command::try_from(append_crc_a(&data).unwrap().as_slice()),
            Ok(Command::Rats(_))
        ));
        assert!(is_invalid_crc(Command::try_from(
            zero_crc(&data).as_slice()
        )));
        assert!(is_invalid_crc(Command::try_from(bad_crc(&data).as_slice())));
        assert!(matches!(
            Command::from_crc_verified(&data),
            Ok(Command::Rats(_))
        ));
    }

    #[test]
    fn command_select() {
        let data = [SEL_CL1, 0x70, 0x01, 0x02, 0x03, 0x04, 0x04];
        assert!(matches!(
            Command::try_from(append_crc_a(&data).unwrap().as_slice()),
            Ok(Command::Select(_))
        ));
        assert!(is_invalid_crc(Command::try_from(
            zero_crc(&data).as_slice()
        )));
        assert!(is_invalid_crc(Command::try_from(bad_crc(&data).as_slice())));
        assert!(matches!(
            Command::from_crc_verified(&data),
            Ok(Command::Select(_))
        ));
    }

    #[test]
    fn command_block() {
        // I-Block, block number 0, two payload bytes
        let data = [0x02, 0xAA, 0xBB];
        assert!(matches!(
            Command::try_from(append_crc_a(&data).unwrap().as_slice()),
            Ok(Command::IBlock(_))
        ));
        assert!(Command::try_from(zero_crc(&data).as_slice()).is_err());
        assert!(Command::try_from(bad_crc(&data).as_slice()).is_err());
        assert!(matches!(
            Command::from_crc_verified(&data),
            Ok(Command::IBlock(_))
        ));
    }

    #[test]
    fn command_pps_request() {
        let data = [0xd0, 0x11, 0x00];
        assert!(matches!(
            Command::try_from(append_crc_a(&data).unwrap().as_slice()),
            Ok(Command::Pps(_))
        ));
        assert!(is_invalid_crc(Command::try_from(
            zero_crc(&data).as_slice()
        )));
        assert!(is_invalid_crc(Command::try_from(bad_crc(&data).as_slice())));
        assert!(matches!(
            Command::from_crc_verified(&data),
            Ok(Command::Pps(_))
        ));
    }

    #[test]
    fn answer_sak() {
        let select = Command::try_from(
            append_crc_a(&[SEL_CL1, 0x70, 0x01, 0x02, 0x03, 0x04, 0x04])
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let data = [0x20];

        let sak = select.parse_answer(append_crc_a(&data).unwrap().as_slice());
        assert!(matches!(sak, Ok(Answer::Sak(_))));
        assert!(is_invalid_crc(
            select.parse_answer(zero_crc(&data).as_slice())
        ));
        assert!(is_invalid_crc(
            select.parse_answer(bad_crc(&data).as_slice())
        ));
        assert!(matches!(
            select.parse_answer_crc_verified(&data),
            Ok(Answer::Sak(_))
        ));

        // Same through the standalone parser
        assert!(Sak::try_from(append_crc_a(&data).unwrap().as_slice()).is_ok());
        assert!(is_invalid_crc(Sak::try_from(zero_crc(&data).as_slice())));
        assert!(is_invalid_crc(Sak::try_from(bad_crc(&data).as_slice())));
        assert!(Sak::from_crc_verified(&data).is_ok());
    }

    #[test]
    fn answer_ats() {
        let rats = Command::Rats(RatsParam::try_from(0x50).unwrap());
        let data = [0x05, 0x78, 0x80, 0x40, 0x02];

        assert!(matches!(
            rats.parse_answer(append_crc_a(&data).unwrap().as_slice()),
            Ok(Answer::Ats(_))
        ));
        assert!(is_invalid_crc(
            rats.parse_answer(zero_crc(&data).as_slice())
        ));
        assert!(is_invalid_crc(rats.parse_answer(bad_crc(&data).as_slice())));
        assert!(matches!(
            rats.parse_answer_crc_verified(&data),
            Ok(Answer::Ats(_))
        ));

        assert!(Ats::try_from(append_crc_a(&data).unwrap().as_slice()).is_ok());
        assert!(is_invalid_crc(Ats::try_from(zero_crc(&data).as_slice())));
        assert!(is_invalid_crc(Ats::try_from(bad_crc(&data).as_slice())));
        assert!(Ats::from_crc_verified(&data).is_ok());
    }

    #[test]
    fn answer_pps_response() {
        let pps = Command::try_from(append_crc_a(&[0xd0, 0x11, 0x00]).unwrap().as_slice()).unwrap();
        let data = [0xd0];

        assert!(matches!(
            pps.parse_answer(append_crc_a(&data).unwrap().as_slice()),
            Ok(Answer::Pps(_))
        ));
        assert!(is_invalid_crc(pps.parse_answer(zero_crc(&data).as_slice())));
        assert!(is_invalid_crc(pps.parse_answer(bad_crc(&data).as_slice())));
        assert!(matches!(
            pps.parse_answer_crc_verified(&data),
            Ok(Answer::Pps(_))
        ));
    }

    #[test]
    fn answer_block() {
        let iblock =
            Command::try_from(append_crc_a(&[0x02, 0xAA, 0xBB]).unwrap().as_slice()).unwrap();
        let data = [0x02, 0x90, 0x00];

        assert!(matches!(
            iblock.parse_answer(append_crc_a(&data).unwrap().as_slice()),
            Ok(Answer::Block(_))
        ));
        assert!(is_invalid_crc(
            iblock.parse_answer(zero_crc(&data).as_slice())
        ));
        assert!(is_invalid_crc(
            iblock.parse_answer(bad_crc(&data).as_slice())
        ));
        assert!(matches!(
            iblock.parse_answer_crc_verified(&data),
            Ok(Answer::Block(_))
        ));

        assert!(Block::try_from(append_crc_a(&data).unwrap().as_slice()).is_ok());
        assert!(is_invalid_crc(Block::try_from(zero_crc(&data).as_slice())));
        assert!(is_invalid_crc(Block::try_from(bad_crc(&data).as_slice())));
        assert!(Block::from_crc_verified(&data).is_ok());
    }

    #[test]
    fn all_zero_crc_is_accepted_when_it_is_the_real_crc() {
        // The sentinel is gone, not the value: data whose calculated CRC_A
        // really is 00 00 still parses. Two free payload bytes map one to
        // one onto the CRC, so exactly one such I-Block exists.
        let mut frame = [0x02, 0x00, 0x00, 0x00, 0x00];
        let found = (0..=u16::MAX).any(|i| {
            frame[1] = (i >> 8) as u8;
            frame[2] = i as u8;
            crc_a(&frame[..3]) == (0, 0)
        });

        assert!(found);
        assert!(Block::try_from(frame.as_slice()).is_ok());
    }

    #[test]
    fn command_serialization_carries_exactly_one_crc() {
        let block =
            Command::try_from(append_crc_a(&[0x02, 0xAA, 0xBB]).unwrap().as_slice()).unwrap();
        let frame = block.to_vec().unwrap();
        assert_eq!(
            frame.as_slice(),
            append_crc_a(&[0x02, 0xAA, 0xBB]).unwrap().as_slice()
        );
        // Round-trips through the wire parser
        assert!(Command::try_from(frame.as_slice()).is_ok());
    }
}
