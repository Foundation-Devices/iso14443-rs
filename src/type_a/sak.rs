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
            if crc_a(&value[..1]) == (value[1], value[2]) || (0, 0) == (value[1], value[2]) {
                Ok(Self {
                    uid_complete: value[0] & 0x04 != 0x04,
                    iso14443_4_compliant: value[0] & 0x20 == 0x20,
                })
            } else {
                Err(TypeAError::InvalidCrc)
            }
        } else {
            Err(TypeAError::InvalidLength)
        }
    }
}
