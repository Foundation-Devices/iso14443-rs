// SPDX-FileCopyrightText: © 2025 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use core::fmt;

use super::Cid;
use super::crc::crc_a;
use super::pcb::{BlockType, Pcb};
use super::vec::{FrameVec, VecExt};

#[derive(Clone, PartialEq, Eq)]
pub struct Block {
    pub pcb: Pcb,
    pub cid: Option<Cid>,
    pub nad: Option<u8>,
    pub payload: FrameVec,
    pub crc: (u8, u8),
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.pcb)?;
        if let Some(cid) = self.cid {
            write!(f, ", CID: {:?}", cid)?;
        }
        if let Some(nad) = self.nad {
            write!(f, ", NAD: {:?}", nad)?;
        }
        if !self.payload.is_empty() {
            write!(f, ", DATA: {:02x?}", self.payload.as_slice())?;
        }
        Ok(())
    }
}

impl Block {
    pub fn new(pcb: Pcb) -> Self {
        Self {
            pcb,
            cid: None,
            nad: None,
            payload: FrameVec::new(),
            crc: (0, 0),
        }
    }

    pub fn with_cid(mut self, cid: Cid) -> Self {
        self.cid = Some(cid);
        self
    }

    pub fn with_nad(mut self, nad: u8) -> Self {
        self.nad = Some(nad);
        self
    }

    pub fn with_payload(mut self, payload: FrameVec) -> Self {
        self.payload = payload;
        self
    }

    pub fn with_crc(mut self, crc: (u8, u8)) -> Self {
        self.crc = crc;
        self
    }

    pub fn is_chaining(&self) -> bool {
        self.pcb.is_chaining()
    }

    pub fn block_number(&self) -> u8 {
        self.pcb.block_number()
    }

    pub fn block_type(&self) -> BlockType {
        self.pcb.block_type
    }

    /// Serialize the block prologue (PCB + optional CID/NAD) and payload,
    /// without CRC bytes. Use this when the transceiver handles CRC in
    /// hardware, or to compute software CRC over the correct data.
    pub fn to_bytes_without_crc(&self) -> Result<FrameVec, super::TypeAError> {
        let mut bytes = FrameVec::new();

        let mut pcb = self.pcb.clone();
        pcb = pcb.with_cid_following(self.cid.is_some());
        pcb = pcb.with_nad_following(self.nad.is_some());

        bytes.try_push(u8::from(pcb))?;

        if let Some(cid) = &self.cid {
            bytes.try_push(cid.value())?;
        }

        if let Some(nad) = self.nad {
            bytes.try_push(nad)?;
        }

        bytes.try_extend(self.payload.as_slice())?;

        Ok(bytes)
    }

    pub fn to_vec(&self) -> Result<FrameVec, super::TypeAError> {
        let mut bytes = self.to_bytes_without_crc()?;

        bytes.try_push(self.crc.0)?;
        bytes.try_push(self.crc.1)?;

        Ok(bytes)
    }

    pub fn calculate_crc(&self) -> Result<(u8, u8), super::TypeAError> {
        let data = self.to_vec()?;
        Ok(crc_a(&data[..data.len() - 2]))
    }

    pub fn validate_crc(&self) -> Result<bool, super::TypeAError> {
        let calculated = self.calculate_crc()?;
        Ok(calculated == self.crc || self.crc == (0, 0))
    }
}

impl TryFrom<&[u8]> for Block {
    type Error = crate::type_a::TypeAError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() < 3 {
            return Err(crate::type_a::TypeAError::InvalidLength);
        }

        let mut offset = 0;

        // Parse PCB
        let pcb = Pcb::try_from(data[offset])?;
        offset += 1;

        // Parse optional CID - only present if PCB indicates CID following
        let mut cid = None;
        if pcb.cid_following() {
            if offset < data.len() {
                let cid_value = data[offset] & 0x0F;
                if cid_value <= 14 {
                    cid = Some(Cid::new(cid_value).unwrap());
                    offset += 1;
                } else {
                    return Err(crate::type_a::TypeAError::UnknownOpcode(data[offset]));
                }
            } else {
                return Err(crate::type_a::TypeAError::InvalidLength);
            }
        }

        // Parse optional NAD - only present for I-blocks when PCB indicates NAD following
        let mut nad = None;
        if pcb.nad_following() {
            // NAD should only be present for I-blocks and only when CID is present
            if pcb.block_type() != BlockType::IBlock {
                return Err(crate::type_a::TypeAError::Other);
            }
            if cid.is_none() {
                return Err(crate::type_a::TypeAError::Other);
            }
            if offset < data.len() {
                nad = Some(data[offset]);
                offset += 1;
            } else {
                return Err(crate::type_a::TypeAError::InvalidLength);
            }
        }

        // Extract payload and CRC
        let remaining_len = data.len() - offset;
        if remaining_len < 2 {
            return Err(crate::type_a::TypeAError::InvalidLength);
        }

        let payload_end = data.len() - 2;
        let mut payload = FrameVec::new();
        payload.try_extend(&data[offset..payload_end])?;
        let crc = (data[payload_end], data[payload_end + 1]);

        let block = Self {
            pcb,
            cid,
            nad,
            payload,
            crc,
        };

        // Validate CRC
        if !block.validate_crc()? {
            return Err(crate::type_a::TypeAError::InvalidCrc(
                block.calculate_crc()?,
            ));
        }

        Ok(block)
    }
}

#[cfg(test)]
mod tests {
    use super::super::pcb::{BlockType, Pcb};
    use super::super::vec::{FrameVec, VecExt};
    use super::*;

    fn frame_vec(data: &[u8]) -> FrameVec {
        let mut v = FrameVec::new();
        v.try_extend(data).unwrap();
        v
    }

    #[test]
    fn test_block_format_iblock_without_optional_fields() {
        let pcb = Pcb::new(BlockType::IBlock).with_block_number(0);
        let block = Block::new(pcb).with_payload(frame_vec(&[0x01, 0x02, 0x03]));
        let bytes = block.to_vec().unwrap();

        assert_eq!(bytes.len(), 6);
        assert_eq!(bytes[0], 0x02);
        assert_eq!(&bytes[1..4], &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_block_format_iblock_with_cid() {
        let pcb = Pcb::new(BlockType::IBlock).with_block_number(1);
        let cid = Cid::new(5).unwrap();
        let block = Block::new(pcb)
            .with_cid(cid)
            .with_payload(frame_vec(&[0x01, 0x02]));
        let bytes = block.to_vec().unwrap();

        assert_eq!(bytes.len(), 6);
        assert_eq!(bytes[0] & 0x08, 0x08);
        assert_eq!(bytes[1], 0x05);
        assert_eq!(&bytes[2..4], &[0x01, 0x02]);
    }

    #[test]
    fn test_block_format_iblock_with_cid_and_nad() {
        let pcb = Pcb::new(BlockType::IBlock).with_block_number(0);
        let cid = Cid::new(3).unwrap();
        let block = Block::new(pcb)
            .with_cid(cid)
            .with_nad(0x12)
            .with_payload(frame_vec(&[0x01]));
        let bytes = block.to_vec().unwrap();

        assert_eq!(bytes.len(), 6);
        assert_eq!(bytes[0] & 0x08, 0x08);
        assert_eq!(bytes[0] & 0x04, 0x04);
        assert_eq!(bytes[1], 0x03);
        assert_eq!(bytes[2], 0x12);
        assert_eq!(bytes[3], 0x01);
    }

    #[test]
    fn test_block_format_rblock_with_cid() {
        let pcb = Pcb::new(BlockType::RBlock)
            .with_block_number(1)
            .with_r_subtype(super::super::pcb::RBlockSubtype::Ack);
        let cid = Cid::new(7).unwrap();
        let block = Block::new(pcb).with_cid(cid);
        let bytes = block.to_vec().unwrap();

        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes[0] & 0x08, 0x08);
        assert_eq!(bytes[0] & 0x04, 0x00);
        assert_eq!(bytes[1], 0x07);
    }

    #[test]
    fn test_block_parsing_iblock_with_cid() {
        let data: &[u8] = &[0x0B, 0x05, 0x01, 0x02, 0x62, 0x95];

        let block = Block::try_from(data).unwrap();
        assert_eq!(block.block_type(), BlockType::IBlock);
        assert_eq!(block.block_number(), 1);
        assert!(block.cid.is_some());
        assert_eq!(block.cid.unwrap().value(), 5);
        assert_eq!(block.payload.as_slice(), &[0x01, 0x02]);
    }

    #[test]
    fn test_block_parsing_rblock_with_cid() {
        let data: &[u8] = &[0xAA, 0x03, 0xb4, 0x7e];

        let block = Block::try_from(data).unwrap();
        assert_eq!(block.block_type(), BlockType::RBlock);
        assert_eq!(block.block_number(), 0);
        assert!(block.cid.is_some());
        assert_eq!(block.cid.unwrap().value(), 3);
        assert!(block.payload.is_empty());
    }

    #[test]
    fn test_block_parsing_rejects_nad_without_cid() {
        let data: &[u8] = &[0x07, 0x12, 0x00, 0x00];

        let result = Block::try_from(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_block_parsing_rejects_nad_for_non_iblock() {
        let data: &[u8] = &[0xAF, 0x03, 0x12, 0x00, 0x00];

        let result = Block::try_from(data);
        assert!(result.is_err());
    }
}
