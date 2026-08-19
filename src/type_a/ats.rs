// SPDX-FileCopyrightText: © 2025 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use core::fmt;

use super::vec::{FrameVec, VecExt};
use super::{TypeAError, crc::split_crc_a};
use bitflags::bitflags;
use num_enum::{IntoPrimitive, TryFromPrimitive};

#[cfg(feature = "std")]
use std::time::Duration;

/// ISO/IEC 14443-4
/// 5.2 Answer to select
#[derive(Debug, Clone)]
pub struct Ats {
    pub length: u8,
    pub format: Format,
    pub ta: Ta,
    pub tb: Tb,
    pub tc: Tc,
    pub historical_bytes: FrameVec,
}

impl Ats {
    /// Serialize ATS to its wire representation (TL + T0 + optional
    /// TA/TB/TC + historical bytes), without CRC.
    pub fn to_bytes(&self) -> Result<FrameVec, TypeAError> {
        let mut data = FrameVec::new();

        // T0: FSCI + presence bits
        let mut t0 = self.format.fsci as u8;
        if self.format.ta_transmitted {
            t0 |= 0b0001_0000;
        }
        if self.format.tb_transmitted {
            t0 |= 0b0010_0000;
        }
        if self.format.tc_transmitted {
            t0 |= 0b0100_0000;
        }

        // TL placeholder (will be updated at the end)
        data.try_push(0)?;
        data.try_push(t0)?;

        if self.format.ta_transmitted {
            data.try_push(self.ta.bits())?;
        }
        if self.format.tb_transmitted {
            data.try_push((self.tb.fwi.0 << 4) | self.tb.sfgi.0)?;
        }
        if self.format.tc_transmitted {
            data.try_push(self.tc.bits())?;
        }

        data.try_extend(self.historical_bytes.as_slice())?;

        // TL = total length including TL byte itself
        data[0] = data.len() as u8;

        Ok(data)
    }

    /// Create an ATS with all interface bytes present.
    pub fn new(fsci: Fsci, ta: Ta, tb: Tb, tc: Tc) -> Self {
        Self {
            length: 0, // computed by to_bytes()
            format: Format {
                fsci,
                ta_transmitted: true,
                tb_transmitted: true,
                tc_transmitted: true,
            },
            ta,
            tb,
            tc,
            historical_bytes: FrameVec::new(),
        }
    }

    /// Parse an ATS whose CRC_A a trusted transceiver has already validated
    /// and stripped: TL, the optional T0/TA(1)/TB(1)/TC(1) interface bytes
    /// and the historical bytes, with no epilogue.
    ///
    /// Use [`Ats::try_from`] for bytes that came off the air unverified.
    ///
    /// TL counts itself and every following ATS byte but not the CRC
    /// (§5.2.2), so it must match `body.len()` exactly. Every field is read
    /// through a checked cursor, so no input can panic:
    ///
    /// - `TL = 0`: invalid, TL always counts at least itself →
    ///   [`TypeAError::InvalidLength`].
    /// - `TL = 1`: shortest legal ATS. T0 is only present when TL is greater
    ///   than 1 (§5.2.3), so the default format applies and there are no
    ///   interface or historical bytes.
    /// - Any advertised interface byte the body is too short to hold →
    ///   [`TypeAError::InvalidLength`].
    pub fn from_crc_verified(body: &[u8]) -> Result<Self, TypeAError> {
        let length = *body.first().ok_or(TypeAError::InvalidLength)?;
        if usize::from(length) != body.len() {
            return Err(TypeAError::InvalidLength);
        }

        let mut offset = 1;
        let format = if length > 1 {
            Format::try_from(take_byte(body, &mut offset)?)?
        } else {
            Format::default()
        };

        let ta = if format.ta_transmitted {
            Ta::from_bits_truncate(take_byte(body, &mut offset)?)
        } else {
            Ta::default()
        };
        let tb = if format.tb_transmitted {
            Tb::try_from(take_byte(body, &mut offset)?)?
        } else {
            Tb::default()
        };
        let tc = if format.tc_transmitted {
            Tc::from_bits_truncate(take_byte(body, &mut offset)?)
        } else {
            Tc::default()
        };

        let mut historical_bytes = FrameVec::new();
        historical_bytes.try_extend(body.get(offset..).ok_or(TypeAError::InvalidLength)?)?;

        Ok(Self {
            length,
            format,
            ta,
            tb,
            tc,
            historical_bytes,
        })
    }
}

/// Read the byte at `offset` and advance it, without ever indexing out of
/// bounds: a truncated ATS yields [`TypeAError::InvalidLength`].
fn take_byte(body: &[u8], offset: &mut usize) -> Result<u8, TypeAError> {
    let byte = *body.get(*offset).ok_or(TypeAError::InvalidLength)?;
    *offset += 1;
    Ok(byte)
}

impl TryFrom<&[u8]> for Ats {
    type Error = TypeAError;

    /// Parse an ATS frame off the wire: the ATS body followed by its two
    /// CRC_A bytes, which must match the data.
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_crc_verified(split_crc_a(value)?)
    }
}

/// ISO/IEC 14443-4
/// Figure 5 - Coding of format byte
#[derive(Debug, Default, Clone)]
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
#[derive(Debug, Default, Clone)]
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

#[derive(Default, Clone)]
pub struct Sfgi(pub(crate) u8);

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

#[derive(Clone)]
pub struct Fwi(pub(crate) u8);

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
    #[derive(Debug, Clone)]
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

#[cfg(test)]
mod parse_tests {
    use super::super::crc::{append_crc_a, crc_a};
    use super::*;

    /// Append the real CRC_A to an ATS body.
    fn with_crc(body: &[u8]) -> FrameVec {
        append_crc_a(body).unwrap()
    }

    #[test]
    fn rejects_frames_shorter_than_the_crc() {
        assert!(matches!(
            Ats::try_from([].as_slice()),
            Err(TypeAError::InvalidLength)
        ));
        assert!(matches!(
            Ats::try_from([0x00].as_slice()),
            Err(TypeAError::InvalidLength)
        ));
        assert!(matches!(
            Ats::try_from([0x01].as_slice()),
            Err(TypeAError::InvalidLength)
        ));
    }

    #[test]
    fn rejects_zero_length_byte() {
        // TL always counts at least itself, so TL = 0 never matches the body.
        assert!(Ats::try_from(with_crc(&[0x00]).as_slice()).is_err());
        assert!(Ats::try_from([0x00, 0x00].as_slice()).is_err());
        assert!(Ats::try_from([0x00, 0x00, 0x00].as_slice()).is_err());
    }

    #[test]
    fn length_one_is_the_shortest_legal_ats() {
        // TL = 1: no T0, so the default format applies (FSCI = 2 → FSC 32)
        // and there are neither interface nor historical bytes. This is the
        // input that used to underflow the historical-byte computation.
        let ats = Ats::try_from(with_crc(&[0x01]).as_slice()).unwrap();
        assert_eq!(ats.length, 1);
        assert_eq!(ats.format.fsci.fsc(), 32);
        assert!(ats.historical_bytes.is_empty());

        // Same shape with the zero-CRC representation must not panic either.
        let _ = Ats::try_from([0x01, 0x00, 0x00].as_slice());
    }

    #[test]
    fn rejects_length_mismatch() {
        // TL = 5 but only two body bytes were transmitted.
        assert!(matches!(
            Ats::try_from(with_crc(&[0x05, 0x78]).as_slice()),
            Err(TypeAError::InvalidLength)
        ));
        // TL = 2 but three body bytes were transmitted.
        assert!(matches!(
            Ats::try_from(with_crc(&[0x02, 0x78, 0x80]).as_slice()),
            Err(TypeAError::InvalidLength)
        ));
    }

    #[test]
    fn rejects_truncated_interface_bytes() {
        // T0 = 0x78 advertises TA(1), TB(1) and TC(1); the body only holds
        // TA(1), so TB(1) runs past the end.
        assert!(matches!(
            Ats::try_from(with_crc(&[0x03, 0x78, 0x80]).as_slice()),
            Err(TypeAError::InvalidLength)
        ));
        // T0 = 0x20 advertises TB(1) alone, which is missing entirely.
        assert!(matches!(
            Ats::try_from(with_crc(&[0x02, 0x20]).as_slice()),
            Err(TypeAError::InvalidLength)
        ));
    }

    #[test]
    fn accepts_full_interface_bytes_and_historical_bytes() {
        // TL = 5, T0 = 0x78 (FSCI 8, TA/TB/TC present), TA/TB/TC, no
        // historical bytes.
        let ats = Ats::try_from(with_crc(&[0x05, 0x78, 0x80, 0x40, 0x02]).as_slice()).unwrap();
        assert_eq!(ats.length, 5);
        assert_eq!(ats.format.fsci.fsc(), 256);
        assert!(ats.historical_bytes.is_empty());

        // Same, plus two historical bytes.
        let ats = Ats::try_from(with_crc(&[0x07, 0x78, 0x80, 0x40, 0x02, 0xAA, 0xBB]).as_slice())
            .unwrap();
        assert_eq!(ats.historical_bytes.as_slice(), &[0xAA, 0xBB]);
    }

    #[test]
    fn accepts_maximum_historical_bytes() {
        // TL = 255: TL + T0 + 253 historical bytes, the largest ATS the
        // length byte can describe. Built as a raw frame because it exceeds
        // the no_std FrameVec capacity by the two CRC bytes.
        let mut frame = [0u8; 257];
        frame[0] = 0xFF;
        frame[1] = 0x02; // T0: FSCI = 2, no interface bytes
        for (i, byte) in frame[2..255].iter_mut().enumerate() {
            *byte = i as u8;
        }
        let (crc1, crc2) = crc_a(&frame[..255]);
        frame[255] = crc1;
        frame[256] = crc2;

        let ats = Ats::try_from(frame.as_slice()).unwrap();
        assert_eq!(ats.length, 255);
        assert_eq!(ats.historical_bytes.len(), 253);
    }

    #[test]
    fn arbitrary_input_never_panics() {
        // Every 0, 1 and 2-byte frame.
        let _ = Ats::try_from([].as_slice());
        for a in 0..=u8::MAX {
            let _ = Ats::try_from([a].as_slice());
            for b in 0..=u8::MAX {
                let _ = Ats::try_from([a, b].as_slice());
            }
        }

        // Pseudo-random longer frames, with the declared length byte biased
        // towards plausible values so the interface-byte paths get exercised.
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut buf = [0u8; 300];
        for _ in 0..20_000 {
            let len = (next() as usize) % buf.len();
            for byte in buf[..len].iter_mut() {
                *byte = next() as u8;
            }
            if len > 0 && next() % 2 == 0 {
                buf[0] = len.saturating_sub(2) as u8;
            }
            let _ = Ats::try_from(&buf[..len]);
        }
    }
}
