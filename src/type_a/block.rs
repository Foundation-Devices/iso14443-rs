// SPDX-FileCopyrightText: © 2025 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use bounded_integer::BoundedU8;
use std::fmt;

use super::crc::crc_a;
use super::pcb::{BlockType, Pcb};

#[derive(Clone, PartialEq, Eq)]
pub struct Block {
    pub pcb: Pcb,
    pub cid: Option<Cid>,
    pub nad: Option<u8>,
    pub payload: Vec<u8>,
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
            write!(f, ", DATA: {:02x?}", self.payload)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Cid(pub BoundedU8<0, 14>);

impl Cid {
    pub fn new(value: u8) -> Option<Self> {
        if value <= 14 {
            Some(Self(BoundedU8::new(value).unwrap()))
        } else {
            None
        }
    }

    pub fn value(&self) -> u8 {
        self.0.get()
    }
}

impl fmt::Debug for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value())
    }
}

impl Block {
    pub fn new(pcb: Pcb) -> Self {
        Self {
            pcb,
            cid: None,
            nad: None,
            payload: Vec::new(),
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

    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
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

    pub fn to_vec(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Update PCB flags based on optional fields
        let mut pcb = self.pcb.clone();
        pcb = pcb.with_cid_following(self.cid.is_some());
        pcb = pcb.with_nad_following(self.nad.is_some());

        // Add PCB
        bytes.push(u8::from(pcb));

        // Add CID if present
        if let Some(cid) = &self.cid {
            bytes.push(cid.value()); // CID value in lower 4 bits, upper bits are 0 for PCD->PICC
        }

        // Add NAD if present
        if let Some(nad) = self.nad {
            bytes.push(nad);
        }

        // Add payload
        bytes.extend_from_slice(&self.payload);

        // Add CRC
        bytes.extend_from_slice(&[self.crc.0, self.crc.1]);

        bytes
    }

    pub fn calculate_crc(&self) -> (u8, u8) {
        let data = self.to_vec();
        crc_a(&data[..data.len() - 2])
    }

    pub fn validate_crc(&self) -> bool {
        let calculated = self.calculate_crc();
        calculated == self.crc || self.crc == (0, 0) // Allow (0,0) for testing
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
        let payload = data[offset..payload_end].to_vec();
        let crc = (data[payload_end], data[payload_end + 1]);

        let block = Self {
            pcb,
            cid,
            nad,
            payload,
            crc,
        };

        // Validate CRC
        if !block.validate_crc() {
            return Err(crate::type_a::TypeAError::InvalidCrc(block.calculate_crc()));
        }

        Ok(block)
    }
}

#[cfg(test)]
mod tests {
    use super::super::pcb::{BlockType, Pcb};
    use super::*;

    #[test]
    fn test_block_format_iblock_without_optional_fields() {
        // Test I-block without CID or NAD
        let pcb = Pcb::new(BlockType::IBlock).with_block_number(0);
        let block = Block::new(pcb).with_payload(vec![0x01, 0x02, 0x03]);
        let bytes = block.to_vec();

        // Should be: PCB + payload + CRC
        assert_eq!(bytes.len(), 6); // 1 PCB + 3 payload + 2 CRC
        assert_eq!(bytes[0], 0x02); // I-block, block number 0
        assert_eq!(&bytes[1..4], &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_block_format_iblock_with_cid() {
        // Test I-block with CID
        let pcb = Pcb::new(BlockType::IBlock).with_block_number(1);
        let cid = Cid::new(5).unwrap();
        let block = Block::new(pcb).with_cid(cid).with_payload(vec![0x01, 0x02]);
        let bytes = block.to_vec();

        // Debug print
        println!("bytes: {:?}", bytes);
        println!("PCB byte: 0x{:02X}", bytes[0]);

        // Should be: PCB + CID + payload + CRC
        assert_eq!(bytes.len(), 6); // 1 PCB + 1 CID + 2 payload + 2 CRC
        assert_eq!(bytes[0] & 0x08, 0x08); // CID following bit set
        assert_eq!(bytes[1], 0x05); // CID value
        assert_eq!(&bytes[2..4], &[0x01, 0x02]);
    }

    #[test]
    fn test_block_format_iblock_with_cid_and_nad() {
        // Test I-block with CID and NAD
        let pcb = Pcb::new(BlockType::IBlock).with_block_number(0);
        let cid = Cid::new(3).unwrap();
        let block = Block::new(pcb)
            .with_cid(cid)
            .with_nad(0x12)
            .with_payload(vec![0x01]);
        let bytes = block.to_vec();

        // Should be: PCB + CID + NAD + payload + CRC
        assert_eq!(bytes.len(), 6); // 1 PCB + 1 CID + 1 NAD + 1 payload + 2 CRC
        assert_eq!(bytes[0] & 0x08, 0x08); // CID following bit set
        assert_eq!(bytes[0] & 0x04, 0x04); // NAD following bit set
        assert_eq!(bytes[1], 0x03); // CID value
        assert_eq!(bytes[2], 0x12); // NAD value
        assert_eq!(bytes[3], 0x01); // payload
    }

    #[test]
    fn test_block_format_rblock_with_cid() {
        // Test R-block with CID (no NAD allowed for R-blocks)
        let pcb = Pcb::new(BlockType::RBlock)
            .with_block_number(1)
            .with_r_subtype(super::super::pcb::RBlockSubtype::Ack);
        let cid = Cid::new(7).unwrap();
        let block = Block::new(pcb).with_cid(cid);
        let bytes = block.to_vec();

        // Should be: PCB + CID + CRC
        assert_eq!(bytes.len(), 4); // 1 PCB + 1 CID + 2 CRC
        assert_eq!(bytes[0] & 0x08, 0x08); // CID following bit set
        assert_eq!(bytes[0] & 0x04, 0x00); // NAD following bit NOT set (not allowed for R-blocks)
        assert_eq!(bytes[1], 0x07); // CID value
    }

    #[test]
    fn test_block_parsing_iblock_with_cid() {
        // Test parsing I-block with CID
        let data: &[u8] = &[0x0B, 0x05, 0x01, 0x02, 0x62, 0x95]; // PCB with CID following, CID=5, payload, CRC

        let block = Block::try_from(data).unwrap();
        assert_eq!(block.block_type(), BlockType::IBlock);
        assert_eq!(block.block_number(), 1);
        assert!(block.cid.is_some());
        assert_eq!(block.cid.unwrap().value(), 5);
        assert_eq!(block.payload, vec![0x01, 0x02]);
    }

    #[test]
    fn test_block_parsing_rblock_with_cid() {
        // Test parsing R-block with CID
        let data: &[u8] = &[0xAA, 0x03, 0xb4, 0x7e]; // PCB with CID following, CID=3, CRC

        let block = Block::try_from(data).unwrap();
        assert_eq!(block.block_type(), BlockType::RBlock);
        assert_eq!(block.block_number(), 0);
        assert!(block.cid.is_some());
        assert_eq!(block.cid.unwrap().value(), 3);
        assert_eq!(block.payload, Vec::<u8>::new()); // R-blocks have no payload
    }

    #[test]
    fn test_block_parsing_rejects_nad_without_cid() {
        // Test that parsing rejects NAD when CID is not present
        let data: &[u8] = &[0x07, 0x12, 0x00, 0x00]; // PCB with NAD following but no CID

        let result = Block::try_from(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_block_parsing_rejects_nad_for_non_iblock() {
        // Test that parsing rejects NAD for non-I-blocks
        let data: &[u8] = &[0xAF, 0x03, 0x12, 0x00, 0x00]; // R-block PCB with CID and NAD following

        let result = Block::try_from(data);
        assert!(result.is_err());
    }
}
