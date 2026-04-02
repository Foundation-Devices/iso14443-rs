// SPDX-FileCopyrightText: © 2025 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::TypeAError;
use super::vec::{FrameVec, VecExt};
use bounded_integer::BoundedU8;

/// 6.4.3 Anticollision and Select

#[derive(Debug, Clone)]
pub enum UidCl {
    Final(u8, u8, u8, u8),
    Next(u8, u8, u8),
}

impl TryFrom<&[u8; 5]> for UidCl {
    type Error = TypeAError;

    fn try_from(value: &[u8; 5]) -> Result<Self, Self::Error> {
        if value.iter().fold(0x00u8, |acc, &x| acc ^ x) != 0 {
            return Err(TypeAError::InvalidBcc);
        }
        match value[0] {
            0x88 => Ok(Self::Next(value[1], value[2], value[3])),
            _ => Ok(Self::Final(value[0], value[1], value[2], value[3])),
        }
    }
}

impl TryFrom<&[u8]> for UidCl {
    type Error = TypeAError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() == 5 {
            Self::try_from(
                <&[u8; 5]>::try_from(value).map_err(|_| TypeAError::UnknownOpcode(value[0]))?,
            )
        } else {
            Err(TypeAError::InvalidLength)
        }
    }
}

/// SEL command codes for each cascade level (ISO14443-3 Table 6).
pub const SEL_CL1: u8 = 0x93;
pub const SEL_CL2: u8 = 0x95;
pub const SEL_CL3: u8 = 0x97;

/// Table 6 - Coding of SEL
#[derive(Debug, Clone)]
#[repr(u8)]
pub enum Cascade {
    Level1(UidCl) = SEL_CL1,
    Level2(UidCl) = SEL_CL2,
    Level3(UidCl) = SEL_CL3,
}

impl Cascade {
    pub(crate) fn check_sel(sel: u8) -> bool {
        sel == SEL_CL1 || sel == SEL_CL2 || sel == SEL_CL3
    }
    pub(crate) fn try_from(sel: u8, uid_cl: &[u8; 5]) -> Result<Self, TypeAError> {
        match sel {
            SEL_CL1 => Ok(Cascade::Level1(UidCl::try_from(uid_cl)?)),
            SEL_CL2 => Ok(Cascade::Level2(UidCl::try_from(uid_cl)?)),
            SEL_CL3 => Ok(Cascade::Level3(UidCl::try_from(uid_cl)?)),
            _ => Err(TypeAError::UnknownOpcode(sel)),
        }
    }
    fn code(&self) -> u8 {
        match self {
            Cascade::Level1(_) => SEL_CL1,
            Cascade::Level2(_) => SEL_CL2,
            Cascade::Level3(_) => SEL_CL3,
        }
    }

    fn uid_cl(&self) -> &UidCl {
        match self {
            Cascade::Level1(uid_cl) => uid_cl,
            Cascade::Level2(uid_cl) => uid_cl,
            Cascade::Level3(uid_cl) => uid_cl,
        }
    }

    pub(crate) fn raw(&self, nvb: u8) -> Result<FrameVec, TypeAError> {
        let mut raw = FrameVec::new();
        raw.try_push(self.code())?;
        raw.try_push(nvb)?;
        match self.uid_cl() {
            UidCl::Final(uid0, uid1, uid2, uid3) => {
                raw.try_push(*uid0)?;
                raw.try_push(*uid1)?;
                raw.try_push(*uid2)?;
                raw.try_push(*uid3)?;
                raw.try_push(*uid0 ^ *uid1 ^ *uid2 ^ uid3)?;
            }
            UidCl::Next(uid0, uid1, uid2) => {
                raw.try_push(0x88)?;
                raw.try_push(*uid0)?;
                raw.try_push(*uid1)?;
                raw.try_push(*uid2)?;
                raw.try_push(*uid0 ^ *uid1 ^ *uid2 ^ 0x88)?;
            }
        }
        Ok(raw)
    }
}

/// Table 7 - Coding of NVB
#[derive(Debug)]
pub struct NumberOfValidBits {
    byte_cnt: BoundedU8<2, 7>,
    bit_cnt: BoundedU8<0, 7>,
}

impl From<&NumberOfValidBits> for u8 {
    fn from(value: &NumberOfValidBits) -> Self {
        (value.byte_cnt.get_ref() << 4) | value.bit_cnt.get_ref()
    }
}

impl TryFrom<u8> for NumberOfValidBits {
    type Error = TypeAError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let byte_cnt =
            <BoundedU8<2, 7>>::new(value >> 4).ok_or(TypeAError::UnknownOpcode(value >> 4))?;
        let bit_cnt =
            <BoundedU8<0, 7>>::new(value & 0xf).ok_or(TypeAError::UnknownOpcode(value & 0xf))?;
        Ok(Self { byte_cnt, bit_cnt })
    }
}

impl NumberOfValidBits {
    /// NVB for initial anticollision: 2 bytes valid (SEL + NVB), no UID bits
    /// known yet. ISO14443-3 Table 7.
    pub fn anticollision() -> Self {
        Self {
            byte_cnt: BoundedU8::new(2).unwrap(),
            bit_cnt: BoundedU8::new(0).unwrap(),
        }
    }

    /// NVB for SELECT: 7 bytes valid (SEL + NVB + UID\[4\] + BCC).
    /// ISO14443-3 Table 7.
    pub fn select() -> Self {
        Self {
            byte_cnt: BoundedU8::new(7).unwrap(),
            bit_cnt: BoundedU8::new(0).unwrap(),
        }
    }

    pub(crate) fn has_40_data_bits(&self) -> bool {
        self.byte_cnt == 7 && self.bit_cnt == 0
    }
}
