use super::TypeAError;
use num_enum::{IntoPrimitive, TryFromPrimitive};

// 6.4.2 ATQA - Answer To Request

/// Table 4 - Coding of b7,b8 for UID size bit frame
#[derive(Debug, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum UidSize {
    Single,
    Double,
    Triple,
}

/// Number of anticollision time slots supported by the PICC.
///
/// ISO14443-3 Table 5 — Coding of b1-b5 for bit frame anticollision.
/// Most tags support a single slot.
#[derive(Debug, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum BitFrameAntiCollision {
    /// 1 time slot.
    Slot1 = 1,
    /// 2 time slots.
    Slot2 = 2,
    /// 4 time slots.
    Slot4 = 4,
    /// 8 time slots.
    Slot8 = 8,
    /// 16 time slots.
    Slot16 = 16,
}

/// Table 3 - Coding of ATQA
#[derive(Debug, Clone)]
pub struct AtqA {
    pub uid_size: UidSize,
    pub bit_frame_ac: BitFrameAntiCollision,
    pub proprietary_coding: u8,
}

impl AtqA {
    /// Serialize ATQA to its 2-byte wire representation.
    pub fn to_bytes(&self) -> [u8; 2] {
        let byte0 = ((self.uid_size.clone() as u8) << 6) | (self.bit_frame_ac.clone() as u8);
        let byte1 = self.proprietary_coding & 0b1111;
        [byte0, byte1]
    }
}

impl TryFrom<&[u8]> for AtqA {
    type Error = TypeAError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() == 2 {
            Ok(Self {
                uid_size: UidSize::try_from((value[0] >> 6) & 0b11)
                    .map_err(|_| TypeAError::UnknownOpcode(value[0] >> 6))?,
                bit_frame_ac: BitFrameAntiCollision::try_from(value[0] & 0b11111)
                    .map_err(|_| TypeAError::UnknownOpcode(value[0] & 0b11111))?,
                proprietary_coding: value[1] & 0b1111,
            })
        } else {
            Err(TypeAError::InvalidLength)
        }
    }
}
