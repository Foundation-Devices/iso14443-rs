// SPDX-FileCopyrightText: © 2025 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use core::fmt;

use super::vec::{FrameVec, VecExt};
use super::{TypeAError, crc::crc_a};
use bitflags::bitflags;
use num_enum::{IntoPrimitive, TryFromPrimitive};

#[cfg(feature = "std")]
use std::time::Duration;

/// ISO/IEC 14443-4
/// 5.2 Answer to select
#[derive(Debug)]
pub struct Ats {
    pub length: u8,
    pub format: Format,
    pub ta: Ta,
    pub tb: Tb,
    pub tc: Tc,
    pub historical_bytes: FrameVec,
}

impl TryFrom<&[u8]> for Ats {
    type Error = TypeAError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(TypeAError::InvalidLength);
        }
        let length = value[0];
        if value.len() != length as usize + 2 {
            return Err(TypeAError::InvalidLength);
        }
        let format = if length > 1 {
            Format::try_from(value[1])?
        } else {
            Format::default()
        };
        let mut offset = 2;
        let ta = if format.ta_transmitted {
            if value.len() >= offset + 2 {
                offset += 1;
                Ok(Ta::from_bits_truncate(value[offset - 1]))
            } else {
                Err(TypeAError::InvalidLength)
            }
        } else {
            Ok(Ta::default())
        }?;
        let tb = if format.tb_transmitted {
            if value.len() >= offset + 2 {
                offset += 1;
                Ok(Tb::try_from(value[offset - 1])?)
            } else {
                Err(TypeAError::InvalidLength)
            }
        } else {
            Ok(Tb::default())
        }?;
        let tc = if format.tc_transmitted {
            if value.len() >= offset + 2 {
                offset += 1;
                Ok(Tc::from_bits_truncate(value[offset - 1]))
            } else {
                Err(TypeAError::InvalidLength)
            }
        } else {
            Ok(Tc::default())
        }?;
        let historical_bytes_len = value.len() - offset - 2;
        let mut historical_bytes = FrameVec::new();
        historical_bytes.try_extend(&value[offset..offset + historical_bytes_len])?;
        offset += historical_bytes_len;
        if value.len() == offset + 2 {
            let crc1 = value[offset];
            let crc2 = value[offset + 1];
            let good = crc_a(&value[..offset]);
            if good == (crc1, crc2) || (0, 0) == (crc1, crc2) {
                Ok(Self {
                    length,
                    format,
                    ta,
                    tb,
                    tc,
                    historical_bytes,
                })
            } else {
                Err(TypeAError::InvalidCrc(good))
            }
        } else {
            Err(TypeAError::InvalidLength)
        }
    }
}

/// ISO/IEC 14443-4
/// Figure 5 - Coding of format byte
#[derive(Debug, Default)]
pub struct Format {
    pub fsci: Fsci,
    ta_transmitted: bool,
    tb_transmitted: bool,
    tc_transmitted: bool,
}

impl TryFrom<u8> for Format {
    type Error = TypeAError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(Self {
            fsci: Fsci::try_from(value & 0b0000_1111).map_err(|_| TypeAError::Other)?,
            ta_transmitted: value & 0b0001_0000 == 0b0001_0000,
            tb_transmitted: value & 0b0010_0000 == 0b0010_0000,
            tc_transmitted: value & 0b0100_0000 == 0b0100_0000,
        })
    }
}

/// ISO/IEC 14443-4
/// Table 1 - FSCI to FSC conversion
#[derive(Default, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum Fsci {
    Fsc16,
    Fsc24,
    #[default]
    Fsc32,
    Fsc40,
    Fsc48,
    Fsc64,
    Fsc96,
    Fsc128,
    Fsc256,
}

impl fmt::Debug for Fsci {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> FSC({} bytes)", *self as u8, self.fsc())
    }
}

impl Fsci {
    /// The FCD defines the maximum size of a frame accepted by the PICC.
    pub fn fsc(&self) -> usize {
        match self {
            Fsci::Fsc16 => 16,
            Fsci::Fsc24 => 24,
            Fsci::Fsc32 => 32,
            Fsci::Fsc40 => 40,
            Fsci::Fsc48 => 48,
            Fsci::Fsc64 => 64,
            Fsci::Fsc96 => 96,
            Fsci::Fsc128 => 128,
            Fsci::Fsc256 => 256,
        }
    }
}

bitflags! {
    /// ISO/IEC 14443-4
    /// 5.2.4 Interface byte TA(1)
    /// Figure 6 - Coding of interface byte TA(1)
    #[derive(Debug, Default, Clone, Copy)]
    pub struct Ta: u8 {
        const DR2_SUPP = 0b0000_0001;
        const DR4_SUPP = 0b0000_0010;
        const DR8_SUPP = 0b0000_0100;
        const DS2_SUPP = 0b0001_0000;
        const DS4_SUPP = 0b0010_0000;
        const DS8_SUPP = 0b0100_0000;
        const SAME_D_SUPP = 0b1000_0000;
    }
}

/// ISO/IEC 14443-4
/// 5.2.5 Interface byte TB(1)
/// Figure 7 - Coding of interface byte TB(1)
#[derive(Debug, Default)]
pub struct Tb {
    pub sfgi: Sfgi,
    pub fwi: Fwi,
}

impl TryFrom<u8> for Tb {
    type Error = TypeAError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(Self {
            sfgi: Sfgi::try_from(value & 0xf)?,
            fwi: Fwi::try_from(value >> 4)?,
        })
    }
}

#[derive(Default)]
pub struct Sfgi(u8);

/// SFGI is coded in the range from 0 to 14.
impl TryFrom<u8> for Sfgi {
    type Error = TypeAError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value <= 14 {
            Ok(Self(value))
        } else {
            Err(TypeAError::Other)
        }
    }
}

#[cfg(feature = "std")]
impl Sfgi {
    /// The SFGT defines a specific guard time needed by the PICC before it is ready to receive the next frame after it has sent the ATS.
    pub fn sfgt(&self) -> Duration {
        // The value of 0 indicates no SFGT needed and the values in the range from 1 to 14 are used to calculate the SFGT with the formula given below.
        if self.0 > 0 {
            Duration::from_micros((256.0 * 16.0 / 13.56) as u64 * (1 << self.0) as u64)
        } else {
            Duration::from_micros(0)
        }
    }
}

#[cfg(feature = "std")]
impl fmt::Debug for Sfgi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> SFGT({:?})", self.0, self.sfgt())
    }
}

#[cfg(not(feature = "std"))]
impl fmt::Debug for Sfgi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SFGI({})", self.0)
    }
}

pub struct Fwi(u8);

impl TryFrom<u8> for Fwi {
    type Error = TypeAError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value <= 14 {
            Ok(Self(value))
        } else {
            Err(TypeAError::Other)
        }
    }
}

/// The default value of FWI is 4, which gives a FWT value of ~ 4,8 ms.
impl Default for Fwi {
    fn default() -> Self {
        Self(4)
    }
}

#[cfg(feature = "std")]
impl fmt::Debug for Fwi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> FWT({:?})", self.0, self.fwt())
    }
}

#[cfg(not(feature = "std"))]
impl fmt::Debug for Fwi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FWI({})", self.0)
    }
}

/// FWT is calculated by the following formula:
/// FWT = (256 x 16 / fc) x 2^FWI
#[cfg(feature = "std")]
impl Fwi {
    pub fn fwt(&self) -> Duration {
        Duration::from_micros((256.0 * 16.0 / 13.56) as u64 * (1 << self.0) as u64)
    }
}

bitflags! {
    /// ISO/IEC 14443-4
    /// 5.2.6 Interface byte TC(1)
    /// Figure 8 - Coding of interface byte TC(1)
    #[derive(Debug)]
    pub struct Tc: u8 {
        const NAD_SUPP = 0b0000_0001;
        const CID_SUPP = 0b0000_0010;
    }
}

/// The default value shall be (10)b indicating CID supported and NAD not supported.
impl Default for Tc {
    fn default() -> Self {
        Self::CID_SUPP
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn sfgt() {
        let sfgi = Sfgi::default();
        assert_eq!(sfgi.sfgt(), Duration::from_micros(0));
        let sfgi = Sfgi::try_from(1u8).unwrap();
        assert_eq!(sfgi.sfgt(), Duration::from_micros(604));
        let sfgi = Sfgi::try_from(14u8).unwrap();
        assert_eq!(sfgi.sfgt(), Duration::from_micros(4947968));
        assert!(Fwi::try_from(15u8).is_err());
    }

    #[test]
    fn fwt() {
        let fwi = Fwi::default();
        assert_eq!(fwi.fwt(), Duration::from_micros(4832));
        let fwi = Fwi::try_from(0u8).unwrap();
        assert_eq!(fwi.fwt(), Duration::from_micros(302));
        let fwi = Fwi::try_from(8u8).unwrap();
        assert_eq!(fwi.fwt(), Duration::from_micros(77312));
        let fwi = Fwi::try_from(9u8).unwrap();
        assert_eq!(fwi.fwt(), Duration::from_micros(154624));
        let fwi = Fwi::try_from(14u8).unwrap();
        assert_eq!(fwi.fwt(), Duration::from_micros(4947968));
        assert!(Fwi::try_from(15u8).is_err());
    }
}
