use super::{TypeAError, crc::crc_a};

/// Table 8 - Coding of SAK
#[derive(Debug, Clone)]
pub struct Sak {
    pub uid_complete: bool,
    pub iso14443_4_compliant: bool,
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
