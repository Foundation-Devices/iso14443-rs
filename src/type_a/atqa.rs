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

/// Table 5 - Coding of b1-b5 for bit frame anticollistion
#[derive(Debug, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum BitFrameAntiCollistion {
    B1 = 1,
    B2 = 2,
    B3 = 4,
    B4 = 8,
    B5 = 16,
}

/// Table 3 - Coding of ATQA
#[derive(Debug, Clone)]
pub struct AtqA {
    pub uid_size: UidSize,
    pub bit_frame_ac: BitFrameAntiCollistion,
    pub proprietary_coding: u8,
}

impl TryFrom<&[u8]> for AtqA {
    type Error = TypeAError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() == 2 {
            Ok(Self {
                uid_size: UidSize::try_from((value[0] >> 6) & 0b11)
                    .map_err(|_| TypeAError::UnknownOpcode(value[0] >> 6))?,
                bit_frame_ac: BitFrameAntiCollistion::try_from(value[0] & 0b11111)
                    .map_err(|_| TypeAError::UnknownOpcode(value[0] & 0b11111))?,
                proprietary_coding: value[1] & 0b1111,
            })
        } else {
            Err(TypeAError::InvalidLength)
        }
    }
}
