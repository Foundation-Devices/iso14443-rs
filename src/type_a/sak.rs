use super::{TypeAError, crc::crc_a};

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

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() == 3 {
            let crc1 = value[1];
            let crc2 = value[2];
            let good = crc_a(&value[..1]);
            if good == (crc1, crc2) || (0, 0) == (crc1, crc2) {
                Ok(Self {
                    uid_complete: value[0] & 0x04 != 0x04,
                    iso14443_4_compliant: value[0] & 0x20 == 0x20,
                })
            } else {
                Err(TypeAError::InvalidCrc(good))
            }
        } else {
            Err(TypeAError::InvalidLength)
        }
    }
}
