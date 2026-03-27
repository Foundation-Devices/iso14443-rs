use bounded_integer::BoundedU8;
use core::fmt;
use num_enum::{IntoPrimitive, TryFromPrimitive};

use super::{Cid, TypeAError, crc_a};

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

impl TryFrom<&[u8]> for PpsParam {
    type Error = TypeAError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 4 {
            return Err(TypeAError::InvalidLength);
        }
        let cid = Cid(<BoundedU8<0, 14>>::new(value[0] & 0xf).ok_or(TypeAError::Other)?);
        let pps1_present = value[1] == 0x11;
        let (dsi, dri) = if pps1_present {
            if value.len() != 5 {
                return Err(TypeAError::InvalidLength);
            }
            (
                Dxi::try_from((value[2] >> 2) & 0b11).map_err(|_| TypeAError::Other)?,
                Dxi::try_from(value[2] & 0b11).map_err(|_| TypeAError::Other)?,
            )
        } else {
            (Dxi::default(), Dxi::default())
        };
        let len = value.len();
        let crc1 = value[len - 2];
        let crc2 = value[len - 1];
        let good = crc_a(&value[..len - 2]);
        if good != (crc1, crc2) && (0, 0) != (crc1, crc2) {
            return Err(TypeAError::InvalidCrc(good));
        }
        Ok(Self { cid, dri, dsi })
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

/// ISO/IEC 14443-4
/// Figure 13 - Protocol and parameter selection response
impl TryFrom<&[u8]> for PpsResp {
    type Error = TypeAError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 3 {
            return Err(TypeAError::InvalidLength);
        }
        let crc1 = value[1];
        let crc2 = value[2];
        let good = crc_a(&value[..1]);
        if good != (crc1, crc2) && (0, 0) != (crc1, crc2) {
            return Err(TypeAError::InvalidCrc(good));
        }
        Ok(Self(Cid(
            <BoundedU8<0, 14>>::new(value[0] & 0xf).ok_or(TypeAError::Other)?
        )))
    }
}
