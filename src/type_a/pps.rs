use bounded_integer::BoundedU8;
use core::fmt;
use num_enum::{IntoPrimitive, TryFromPrimitive};

use super::{Cid, TypeAError, crc::split_crc_a};

impl From<&Cid> for u8 {
    fn from(value: &Cid) -> Self {
        value.0.get()
    }
}

/// ISO/IEC 14443-4
/// 5.3 Protocol and parameter selection request
/// Figure 9 - Protocol and parameter selection request
#[derive(Debug)]
pub struct PpsParam {
    pub cid: Cid,
    pub dri: Dxi,
    pub dsi: Dxi,
}

impl From<&PpsParam> for u8 {
    fn from(value: &PpsParam) -> Self {
        ((value.dsi as u8) << 2) | (value.dri as u8)
    }
}

impl PpsParam {
    /// Parse a PPS request whose CRC_A a trusted transceiver has already
    /// validated and stripped: PPSS, PPS0 and the optional PPS1, with no
    /// epilogue.
    ///
    /// Use [`PpsParam::try_from`] for bytes that came off the air unverified.
    pub fn from_crc_verified(value: &[u8]) -> Result<Self, TypeAError> {
        if value.len() < 2 {
            return Err(TypeAError::InvalidLength);
        }
        let cid = Cid(<BoundedU8<0, 14>>::new(value[0] & 0xf).ok_or(TypeAError::Other)?);
        let pps1_present = value[1] == 0x11;
        let (dsi, dri) = if pps1_present {
            if value.len() != 3 {
                return Err(TypeAError::InvalidLength);
            }
            (
                Dxi::try_from((value[2] >> 2) & 0b11).map_err(|_| TypeAError::Other)?,
                Dxi::try_from(value[2] & 0b11).map_err(|_| TypeAError::Other)?,
            )
        } else {
            if value.len() != 2 {
                return Err(TypeAError::InvalidLength);
            }
            (Dxi::default(), Dxi::default())
        };
        Ok(Self { cid, dri, dsi })
    }
}

impl TryFrom<&[u8]> for PpsParam {
    type Error = TypeAError;

    /// Parse a PPS request off the wire: the request bytes followed by their
    /// two CRC_A bytes, which must match the data.
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_crc_verified(split_crc_a(value)?)
    }
}

/// ISO/IEC 14443-4
/// Table 2 - DRI, DSI to D conversion
#[derive(Default, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum Dxi {
    #[default]
    Dx1,
    Dx2,
    Dx4,
    Dx8,
}

impl fmt::Debug for Dxi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> Dx({})", *self as u8, self.dx())
    }
}

impl Dxi {
    /// The DS defines the bit rate capability of the PICC for the direction from PICC to PCD.
    /// The DR defines the bit rate capability of the PICC for the direction from PCD to PICC.
    pub fn dx(&self) -> usize {
        match self {
            Dxi::Dx1 => 1,
            Dxi::Dx2 => 2,
            Dxi::Dx4 => 4,
            Dxi::Dx8 => 8,
        }
    }
}

/// ISO/IEC 14443-4
/// 5.4 - Protocol and parameter selection response
#[derive(Debug)]
pub struct PpsResp(pub Cid);

impl PpsResp {
    /// Parse a PPS response whose CRC_A a trusted transceiver has already
    /// validated and stripped: the PPSS byte, with no epilogue.
    ///
    /// Use [`PpsResp::try_from`] for bytes that came off the air unverified.
    pub fn from_crc_verified(value: &[u8]) -> Result<Self, TypeAError> {
        match value {
            [ppss] => Ok(Self(Cid(
                <BoundedU8<0, 14>>::new(ppss & 0xf).ok_or(TypeAError::Other)?
            ))),
            _ => Err(TypeAError::InvalidLength),
        }
    }
}

/// ISO/IEC 14443-4
/// Figure 13 - Protocol and parameter selection response
impl TryFrom<&[u8]> for PpsResp {
    type Error = TypeAError;

    /// Parse a PPS response off the wire: the PPSS byte followed by its two
    /// CRC_A bytes, which must match the data.
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_crc_verified(split_crc_a(value)?)
    }
}
