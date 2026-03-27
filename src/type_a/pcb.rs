// SPDX-FileCopyrightText: © 2025 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use bitflags::bitflags;
use bounded_integer::BoundedU8;
use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockType {
    IBlock, // Information block
    RBlock, // Receive acknowledgment block
    SBlock, // Supervisory block
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RBlockSubtype {
    Ack, // Acknowledgment
    Nak, // Negative acknowledgment
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SBlockSubtype {
    Deselect, // DESELECT
    Wtx,      // Waiting time extension
    RBlock,   // R-block response
    SBlock,   // S-block response
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PcbFlags: u8 {
        const BLOCK_NUMBER = 0b00000001;
        const BIT_1_RESERVED = 0b00000010;
        const CID_FOLLOWING = 0b00001000;
        const NAD_FOLLOWING = 0b00000100;
        const CHAINING = 0b00010000;
        const BLOCK_TYPE_MASK = 0b11000000;
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Pcb {
    pub flags: PcbFlags,
    pub block_type: BlockType,
    pub block_number: BoundedU8<0, 1>,
    pub chaining: bool,
    pub r_subtype: Option<RBlockSubtype>,
    pub s_subtype: Option<SBlockSubtype>,
}

impl fmt::Debug for Pcb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}({})", self.block_type(), self.block_number())?;
        if let Some(sub) = self.s_subtype {
            write!(f, " -> {:?}", sub)?;
        }
        if let Some(sub) = self.r_subtype {
            write!(f, " -> {:?}", sub)?;
        }
        if self.chaining {
            write!(f, " [Chaining]")?;
        }
        Ok(())
    }
}

impl Pcb {
    pub fn new(block_type: BlockType) -> Self {
        Self {
            flags: PcbFlags::empty(),
            block_type,
            block_number: BoundedU8::new(0).unwrap(),
            chaining: false,
            r_subtype: None,
            s_subtype: None,
        }
    }

    pub fn with_block_number(mut self, block_number: u8) -> Self {
        self.block_number = BoundedU8::new(block_number & 1).unwrap();
        if self.block_number.get() == 1 {
            self.flags |= PcbFlags::BLOCK_NUMBER;
        }
        self
    }

    pub fn with_chaining(mut self, chaining: bool) -> Self {
        self.chaining = chaining;
        if chaining {
            self.flags |= PcbFlags::CHAINING;
        }
        self
    }

    pub fn with_r_subtype(mut self, subtype: RBlockSubtype) -> Self {
        self.r_subtype = Some(subtype);
        self
    }

    pub fn with_s_subtype(mut self, subtype: SBlockSubtype) -> Self {
        self.s_subtype = Some(subtype);
        self
    }

    pub fn with_cid_following(mut self, cid_following: bool) -> Self {
        if cid_following {
            self.flags |= PcbFlags::CID_FOLLOWING;
        } else {
            self.flags &= !PcbFlags::CID_FOLLOWING;
        }
        self
    }

    pub fn with_nad_following(mut self, nad_following: bool) -> Self {
        if nad_following {
            self.flags |= PcbFlags::NAD_FOLLOWING;
        } else {
            self.flags &= !PcbFlags::NAD_FOLLOWING;
        }
        self
    }

    pub fn is_chaining(&self) -> bool {
        self.chaining
    }

    pub fn block_number(&self) -> u8 {
        self.block_number.get()
    }

    pub fn cid_following(&self) -> bool {
        self.flags.contains(PcbFlags::CID_FOLLOWING)
    }

    pub fn nad_following(&self) -> bool {
        self.flags.contains(PcbFlags::NAD_FOLLOWING)
    }

    pub fn block_type(&self) -> BlockType {
        self.block_type
    }
}

impl TryFrom<u8> for Pcb {
    type Error = crate::type_a::TypeAError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        let flags = PcbFlags::from_bits_truncate(byte);
        let block_type_bits = byte & PcbFlags::BLOCK_TYPE_MASK.bits();

        let block_type = match block_type_bits {
            0b0000_0000 => BlockType::IBlock,
            0b1000_0000 => BlockType::RBlock,
            0b1100_0000 => BlockType::SBlock,
            _ => return Err(crate::type_a::TypeAError::InvalidPcb),
        };

        // Check that bit 1 is always set to 1 for I-blocks, R-blocks, and S-blocks
        if byte & 0b0000_0010 == 0 {
            return Err(crate::type_a::TypeAError::InvalidPcb);
        }

        // For I-blocks, bit 5 should always be 0
        if block_type == BlockType::IBlock && (byte & 0b0010_0000 != 0) {
            return Err(crate::type_a::TypeAError::InvalidPcb);
        }

        // For R-blocks, bit 5 should always be 1
        if block_type == BlockType::RBlock && (byte & 0b0010_0000 == 0) {
            return Err(crate::type_a::TypeAError::InvalidPcb);
        }

        let block_number = if flags.contains(PcbFlags::BLOCK_NUMBER) {
            1
        } else {
            0
        };

        // Chaining is only valid for I-blocks
        let chaining = if block_type == BlockType::IBlock {
            flags.contains(PcbFlags::CHAINING)
        } else {
            false
        };

        let (r_subtype, s_subtype) = match block_type {
            BlockType::RBlock => {
                // R-block: bit 4 indicates ACK/NAK (0=ACK, 1=NAK)
                let subtype_bits = (byte >> 4) & 0x01;
                let subtype = match subtype_bits {
                    0 => RBlockSubtype::Ack,
                    1 => RBlockSubtype::Nak,
                    _ => unreachable!(),
                };
                (Some(subtype), None)
            }
            BlockType::SBlock => {
                // S-block: bits 4-5 indicate subtype (00=DESELECT, 11=WTX)
                let subtype_bits = (byte >> 4) & 0x03;
                let subtype = match subtype_bits {
                    0b00 => SBlockSubtype::Deselect,
                    0b11 => SBlockSubtype::Wtx,
                    _ => return Err(crate::type_a::TypeAError::InvalidPcb),
                };
                (None, Some(subtype))
            }
            BlockType::IBlock => (None, None),
        };

        Ok(Self {
            flags,
            block_type,
            block_number: BoundedU8::new(block_number).unwrap(),
            chaining,
            r_subtype,
            s_subtype,
        })
    }
}

impl From<Pcb> for u8 {
    fn from(pcb: Pcb) -> u8 {
        let mut byte = 0b0000_0010;

        // Set block type bits (bits 6-7)
        match pcb.block_type {
            BlockType::IBlock => byte |= 0b0000_0000,
            BlockType::RBlock => byte |= 0b1000_0000,
            BlockType::SBlock => byte |= 0b1100_0000,
        }

        // Set block number (bit 0)
        if pcb.block_number.get() == 1 {
            byte |= PcbFlags::BLOCK_NUMBER.bits();
        }

        // Set chaining bit (bit 4) - only for I-blocks
        if pcb.chaining {
            byte |= PcbFlags::CHAINING.bits();
        }

        // Set CID and NAD following bits from flags
        byte |=
            pcb.flags.bits() & (PcbFlags::CID_FOLLOWING.bits() | PcbFlags::NAD_FOLLOWING.bits());

        // Set subtype bits for R-block and S-block
        match pcb.block_type {
            BlockType::RBlock => {
                byte |= 0b0010_0000; // Set bit 5
                if let Some(subtype) = pcb.r_subtype {
                    match subtype {
                        RBlockSubtype::Ack => byte &= !0b00010000, // Clear bit 4
                        RBlockSubtype::Nak => byte |= 0b00010000,  // Set bit 4
                    }
                }
            }
            BlockType::SBlock => {
                if let Some(subtype) = pcb.s_subtype {
                    match subtype {
                        SBlockSubtype::Deselect => byte |= 0b00000000, // Bits 4-5 = 00
                        SBlockSubtype::Wtx => byte |= 0b00110000,      // Bits 4-5 = 11
                        _ => {} // Other subtypes not used in current implementation
                    }
                }
            }
            BlockType::IBlock => {} // No subtype for I-block
        }

        byte
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcb_iblock_parsing() {
        let pcb = Pcb::try_from(0x02).unwrap(); // I-block, no chaining, block number 0
        assert_eq!(pcb.block_type, BlockType::IBlock);
        assert_eq!(pcb.block_number(), 0);
        assert!(!pcb.chaining);
        assert_eq!(pcb.r_subtype, None);
        assert_eq!(pcb.s_subtype, None);
    }

    #[test]
    fn test_pcb_iblock_with_chaining() {
        let pcb = Pcb::try_from(0x13).unwrap(); // I-block, chaining, block number 1
        assert_eq!(pcb.block_type, BlockType::IBlock);
        assert_eq!(pcb.block_number(), 1);
        assert!(pcb.chaining);
    }

    #[test]
    fn test_pcb_rblock_ack() {
        let pcb = Pcb::try_from(0xA2).unwrap(); // R-block ACK, block number 0
        assert_eq!(pcb.block_type, BlockType::RBlock);
        assert_eq!(pcb.r_subtype, Some(RBlockSubtype::Ack));
        assert_eq!(pcb.block_number(), 0);
        assert!(!pcb.chaining); // R-blocks should never have chaining
    }

    #[test]
    fn test_pcb_rblock_nak() {
        let pcb = Pcb::try_from(0xB2).unwrap(); // R-block NAK, block number 0
        assert_eq!(pcb.block_type, BlockType::RBlock);
        assert_eq!(pcb.r_subtype, Some(RBlockSubtype::Nak));
        assert!(!pcb.chaining); // R-blocks should never have chaining
    }

    #[test]
    fn test_pcb_sblock_deselect() {
        let pcb = Pcb::try_from(0xc2).unwrap(); // S-block DESELECT
        assert_eq!(pcb.block_type, BlockType::SBlock);
        assert_eq!(pcb.s_subtype, Some(SBlockSubtype::Deselect));
    }

    #[test]
    fn test_pcb_sblock_wtx() {
        let pcb = Pcb::try_from(0xf2).unwrap(); // S-block WTX
        assert_eq!(pcb.block_type, BlockType::SBlock);
        assert_eq!(pcb.s_subtype, Some(SBlockSubtype::Wtx));
    }

    #[test]
    fn test_pcb_roundtrip_comprehensive() {
        // Test all possible u8 values for roundtrip consistency
        for byte in 0u8..=255 {
            if let Ok(pcb) = Pcb::try_from(byte) {
                let converted: u8 = pcb.clone().into();
                assert_eq!(
                    byte, converted,
                    "Roundtrip failed for 0x{:02X}: got 0x{:02X}",
                    byte, converted
                );
            }
            // If parsing fails, that's expected for invalid values
        }
    }

    #[test]
    fn test_pcb_rejects_bit_1_clear() {
        // Test that PCB parsing rejects bytes with bit 1 clear (should always be set)
        let invalid_bytes = [
            0x00, 0x01, 0x04, 0x05, 0x40, 0x41, 0x44, 0x45, 0x80, 0x81, 0x84, 0x85,
        ]; // Various block types with bit 1 clear

        for &byte in &invalid_bytes {
            let result = Pcb::try_from(byte);
            assert!(
                result.is_err(),
                "Byte 0x{:02X} with bit 1 clear should be rejected",
                byte
            );
        }
    }

    #[test]
    fn test_pcb_iblock_rejects_bit_5_set() {
        // Test that I-block PCB parsing rejects bytes with bit 5 set (should always be 0)
        let invalid_iblock_bytes = [
            0x22, 0x23, 0x26, 0x27, 0x2A, 0x2B, 0x2E, 0x2F, // Various I-blocks with bit 5 set
        ];

        for &byte in &invalid_iblock_bytes {
            let result = Pcb::try_from(byte);
            assert!(
                result.is_err(),
                "I-block byte 0x{:02X} with bit 5 set should be rejected",
                byte
            );
        }

        // Test that valid I-blocks (bit 5 = 0) are accepted
        let valid_iblock_bytes = [0x02, 0x03, 0x12, 0x13, 0x0A, 0x0B, 0x1A, 0x1B];

        for &byte in &valid_iblock_bytes {
            let result = Pcb::try_from(byte);
            assert!(
                result.is_ok(),
                "Valid I-block byte 0x{:02X} should be accepted",
                byte
            );
            if let Ok(pcb) = result {
                assert_eq!(pcb.block_type, BlockType::IBlock);
            }
        }
    }

    #[test]
    fn test_pcb_rblock_requires_bit_5_set() {
        // Test that R-block PCB parsing rejects bytes with bit 5 clear (should always be 1)
        let invalid_rblock_bytes = [
            0x82, 0x83, 0x86, 0x87, 0x8A, 0x8B, 0x8E,
            0x8F, // Various R-blocks with bit 5 clear
        ];

        for &byte in &invalid_rblock_bytes {
            let result = Pcb::try_from(byte);
            assert!(
                result.is_err(),
                "R-block byte 0x{:02X} with bit 5 clear should be rejected",
                byte
            );
        }

        // Test that valid R-blocks (bit 5 = 1) are accepted
        let valid_rblock_bytes = [0xA2, 0xA3, 0xB2, 0xB3, 0xAA, 0xAB, 0xBA, 0xBB];

        for &byte in &valid_rblock_bytes {
            let result = Pcb::try_from(byte);
            assert!(
                result.is_ok(),
                "Valid R-block byte 0x{:02X} should be accepted",
                byte
            );
            if let Ok(pcb) = result {
                assert_eq!(pcb.block_type, BlockType::RBlock);
            }
        }
    }

    #[test]
    fn test_pcb_builder() {
        let pcb = Pcb::new(BlockType::IBlock)
            .with_block_number(1)
            .with_chaining(true);

        assert_eq!(pcb.block_type, BlockType::IBlock);
        assert_eq!(pcb.block_number(), 1);
        assert!(pcb.chaining);
    }
}
