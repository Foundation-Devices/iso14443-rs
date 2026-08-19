use super::{TypeAError, crc::split_crc_a};

/// Table 8 - Coding of SAK
#[derive(Debug, Clone)]
pub struct Sak {
    pub uid_complete: bool,
    pub iso14443_4_compliant: bool,
}

impl Sak {
    /// Parse SAK from a raw byte (no CRC). Use when hardware CRC is enabled
    /// and the transceiver has already validated and stripped the CRC.
    pub fn from_raw(sak: u8) -> Self {
        Self {
            uid_complete: sak & 0x04 != 0x04,
            iso14443_4_compliant: sak & 0x20 == 0x20,
        }
    }

    /// Parse a SAK whose CRC_A a trusted transceiver has already validated
    /// and stripped: the single SAK byte, with no epilogue.
    ///
    /// Use [`Sak::try_from`] for bytes that came off the air unverified.
    pub fn from_crc_verified(value: &[u8]) -> Result<Self, TypeAError> {
        match value {
            [sak] => Ok(Self::from_raw(*sak)),
            _ => Err(TypeAError::InvalidLength),
        }
    }

    /// Serialize SAK to its single-byte wire representation (without CRC).
    pub fn to_byte(&self) -> u8 {
        let mut sak = 0u8;
        if !self.uid_complete {
            sak |= 0x04;
        }
        if self.iso14443_4_compliant {
            sak |= 0x20;
        }
        sak
    }
}

impl TryFrom<&[u8]> for Sak {
    type Error = TypeAError;

    /// Parse a SAK frame off the wire: the SAK byte followed by its two
    /// CRC_A bytes, which must match the data.
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_crc_verified(split_crc_a(value)?)
    }
}
