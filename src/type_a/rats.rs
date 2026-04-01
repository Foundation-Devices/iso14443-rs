use bounded_integer::BoundedU8;
use core::fmt;
use num_enum::{IntoPrimitive, TryFromPrimitive};

use super::{Cid, TypeAError};

/// ISO/IEC 14443-4
/// 5.1 Request for answer to select
/// Figure 3 - Coding of RATS paramter byte
pub struct RatsParam(Fsdi, Cid);

impl RatsParam {
    pub fn new(fsdi: Fsdi, cid: Cid) -> Self {
        Self(fsdi, cid)
    }

    pub fn fsdi(&self) -> Fsdi {
        self.0
    }

    pub fn cid(&self) -> &Cid {
        &self.1
    }
}

impl From<&RatsParam> for u8 {
    fn from(value: &RatsParam) -> Self {
        ((value.0 as u8) << 4) | (value.1.0)
    }
}

impl fmt::Debug for RatsParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RatsParam(fsdi: {:?}, cid: {:?})", self.0, self.1)
    }
}

impl TryFrom<u8> for RatsParam {
    type Error = TypeAError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let fsdi = Fsdi::try_from(value >> 4).map_err(|_| TypeAError::Other)?;
        let cid = Cid(<BoundedU8<0, 14>>::new(value & 0xf).ok_or(TypeAError::Other)?);
        Ok(Self(fsdi, cid))
    }
}

/// ISO/IEC 14443-4
/// Table 1 - FSDI to FSD conversion
#[derive(Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum Fsdi {
    Fsd16,
    Fsd24,
    Fsd32,
    Fsd40,
    Fsd48,
    Fsd64,
    Fsd96,
    Fsd128,
    Fsd256,
}

impl fmt::Debug for Fsdi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> FSD({} bytes)", *self as u8, self.fsd())
    }
}

impl Fsdi {
    /// The FSD defines the maximum size of a frame the PCD is able to receive.
    pub fn fsd(&self) -> usize {
        match self {
            Fsdi::Fsd16 => 16,
            Fsdi::Fsd24 => 24,
            Fsdi::Fsd32 => 32,
            Fsdi::Fsd40 => 40,
            Fsdi::Fsd48 => 48,
            Fsdi::Fsd64 => 64,
            Fsdi::Fsd96 => 96,
            Fsdi::Fsd128 => 128,
            Fsdi::Fsd256 => 256,
        }
    }
}
