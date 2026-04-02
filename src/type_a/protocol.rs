// SPDX-FileCopyrightText: © 2025 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Generic ISO14443-4 block protocol handler.
//!
//! Role-agnostic: manages block numbering, block construction (with optional
//! CID), and chain accumulation. Returns [`Action`]s that the caller (PCD or
//! PICC transport layer) must execute.

use super::pcb::Pcb;
use super::vec::{ChainVec, FrameVec, VecExt};
use super::{Block, BlockType, Cid, RBlockSubtype, SBlockSubtype, TypeAError};

/// Action the caller must take after processing a received block.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // ChainVec is large in no_std (heapless); boxing requires alloc
pub enum Action {
    /// The received I-Block completes the exchange (single block or final
    /// block of a chain). The assembled payload is returned.
    Complete(ChainVec),
    /// The caller must send this block to continue the protocol:
    /// R(ACK) during chaining, S(WTX) echo, or S(DESELECT) echo.
    Reply(Block),
    /// R(ACK) received with matching block number during our chaining.
    /// Caller should send the next chained I-Block.
    ChainingAck,
    /// R(ACK) received with non-matching block number during our chaining.
    /// Caller should retransmit the last I-Block.
    ChainingRetransmit,
}

/// Generic ISO14443-4 block protocol state.
///
/// Tracks block numbering, optional CID, and chain accumulation.
/// Both PCD and PICC transport layers use this for the shared block-level
/// protocol, adding their role-specific logic (I/O, CRC, error recovery)
/// on top.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolHandler {
    cid: Option<Cid>,
    block_number: u8,
    chain: ChainVec,
}

impl ProtocolHandler {
    pub fn new(cid: Option<Cid>) -> Self {
        Self {
            cid,
            block_number: 0,
            chain: ChainVec::new(),
        }
    }

    pub fn block_number(&self) -> u8 {
        self.block_number
    }

    pub fn toggle_block_number(&mut self) {
        self.block_number = 1 - self.block_number;
    }

    pub fn reset(&mut self) {
        self.block_number = 0;
        self.chain.clear();
    }

    /// Reset chain accumulator between exchanges.
    pub fn reset_chain(&mut self) {
        self.chain.clear();
    }

    // ── Block builders ──────────────────────────────────────────────────

    pub fn build_iblock(&self, payload: &[u8], chaining: bool) -> Result<Block, TypeAError> {
        let pcb = Pcb::new(BlockType::IBlock)
            .with_block_number(self.block_number)
            .with_chaining(chaining);
        let mut block = Block::new(pcb);
        if let Some(cid) = self.cid {
            block = block.with_cid(cid);
        }
        let mut p = FrameVec::new();
        p.try_extend(payload)?;
        Ok(block.with_payload(p))
    }

    pub fn build_rack(&self) -> Result<Block, TypeAError> {
        let pcb = Pcb::new(BlockType::RBlock)
            .with_block_number(self.block_number)
            .with_r_subtype(RBlockSubtype::Ack);
        let mut block = Block::new(pcb);
        if let Some(cid) = self.cid {
            block = block.with_cid(cid);
        }
        Ok(block)
    }

    pub fn build_rnak(&self) -> Result<Block, TypeAError> {
        let pcb = Pcb::new(BlockType::RBlock)
            .with_block_number(self.block_number)
            .with_r_subtype(RBlockSubtype::Nak);
        let mut block = Block::new(pcb);
        if let Some(cid) = self.cid {
            block = block.with_cid(cid);
        }
        Ok(block)
    }

    pub fn build_sblock(&self, subtype: SBlockSubtype) -> Result<Block, TypeAError> {
        let pcb = Pcb::new(BlockType::SBlock).with_s_subtype(subtype);
        let mut block = Block::new(pcb);
        if let Some(cid) = self.cid {
            block = block.with_cid(cid);
        }
        Ok(block)
    }

    pub fn build_wtx_response(&self, request: &Block) -> Result<Block, TypeAError> {
        let pcb = Pcb::new(BlockType::SBlock).with_s_subtype(SBlockSubtype::Wtx);
        let mut block = Block::new(pcb);
        if let Some(cid) = self.cid {
            block = block.with_cid(cid);
        }
        Ok(block.with_payload(request.payload.clone()))
    }

    // ── Incoming block processing ───────────────────────────────────────

    /// Process a received block and return the action the caller must take.
    ///
    /// Handles:
    /// - I-Block (single or chained) → accumulate, return [`Action::Complete`]
    ///   or [`Action::Reply`] with R(ACK).
    /// - R(ACK) → return [`Action::ChainingAck`] or
    ///   [`Action::ChainingRetransmit`] based on block number match.
    /// - S(WTX) → return [`Action::Reply`] with S(WTX) echo.
    /// - S(DESELECT) → return [`Action::Reply`] with S(DESELECT) echo, reset.
    pub fn process_received(&mut self, block: Block) -> Result<Action, TypeAError> {
        match block.block_type() {
            BlockType::IBlock => self.process_iblock(block),
            BlockType::RBlock => self.process_rblock(block),
            BlockType::SBlock => self.process_sblock(block),
        }
    }

    fn process_iblock(&mut self, block: Block) -> Result<Action, TypeAError> {
        self.chain.try_extend(block.payload.as_slice())?;

        if block.is_chaining() {
            // R(ACK) carries the received block's number (before toggle)
            let rack = self.build_rack()?;
            self.toggle_block_number();
            Ok(Action::Reply(rack))
        } else {
            self.toggle_block_number();
            let mut data = ChainVec::new();
            core::mem::swap(&mut data, &mut self.chain);
            Ok(Action::Complete(data))
        }
    }

    fn process_rblock(&mut self, block: Block) -> Result<Action, TypeAError> {
        match block.pcb.r_subtype {
            Some(RBlockSubtype::Ack) => {
                if block.block_number() == self.block_number {
                    self.toggle_block_number();
                    Ok(Action::ChainingAck)
                } else {
                    Ok(Action::ChainingRetransmit)
                }
            }
            Some(RBlockSubtype::Nak) => {
                // NAK → caller should retransmit last block
                Ok(Action::ChainingRetransmit)
            }
            None => Err(TypeAError::InvalidPcb),
        }
    }

    fn process_sblock(&mut self, block: Block) -> Result<Action, TypeAError> {
        match block.pcb.s_subtype {
            Some(SBlockSubtype::Wtx) => {
                let resp = self.build_wtx_response(&block)?;
                Ok(Action::Reply(resp))
            }
            Some(SBlockSubtype::Deselect) => {
                let resp = self.build_sblock(SBlockSubtype::Deselect)?;
                self.reset();
                Ok(Action::Reply(resp))
            }
            _ => Err(TypeAError::Other),
        }
    }
}

impl Default for ProtocolHandler {
    fn default() -> Self {
        Self::new(None)
    }
}

#[cfg(test)]
mod tests {
    use super::super::pcb::Pcb;
    use super::super::vec::{FrameVec, VecExt};
    use super::*;

    fn frame_vec(data: &[u8]) -> FrameVec {
        let mut v = FrameVec::new();
        v.try_extend(data).unwrap();
        v
    }

    fn iblock(block_number: u8, payload: &[u8], chaining: bool) -> Block {
        let pcb = Pcb::new(BlockType::IBlock)
            .with_block_number(block_number)
            .with_chaining(chaining);
        Block::new(pcb).with_payload(frame_vec(payload))
    }

    fn rack(block_number: u8) -> Block {
        let pcb = Pcb::new(BlockType::RBlock)
            .with_block_number(block_number)
            .with_r_subtype(RBlockSubtype::Ack);
        Block::new(pcb)
    }

    fn rnak(block_number: u8) -> Block {
        let pcb = Pcb::new(BlockType::RBlock)
            .with_block_number(block_number)
            .with_r_subtype(RBlockSubtype::Nak);
        Block::new(pcb)
    }

    fn sblock_wtx(wtxm: u8) -> Block {
        let pcb = Pcb::new(BlockType::SBlock).with_s_subtype(SBlockSubtype::Wtx);
        Block::new(pcb).with_payload(frame_vec(&[wtxm]))
    }

    fn sblock_deselect() -> Block {
        let pcb = Pcb::new(BlockType::SBlock).with_s_subtype(SBlockSubtype::Deselect);
        Block::new(pcb)
    }

    // ── Block builder tests ─────────────────────────────────────────────

    #[test]
    fn build_iblock_with_cid() {
        let handler = ProtocolHandler::new(Some(Cid::new(3).unwrap()));
        let block = handler.build_iblock(&[0x01, 0x02], false).unwrap();

        assert_eq!(block.block_type(), BlockType::IBlock);
        assert_eq!(block.block_number(), 0);
        assert!(!block.is_chaining());
        assert_eq!(block.cid.unwrap().value(), 3);
        assert_eq!(block.payload.as_slice(), &[0x01, 0x02]);
    }

    #[test]
    fn build_iblock_without_cid() {
        let handler = ProtocolHandler::new(None);
        let block = handler.build_iblock(&[0xAA], true).unwrap();

        assert!(block.cid.is_none());
        assert!(block.is_chaining());
    }

    #[test]
    fn build_rack_with_correct_block_number() {
        let mut handler = ProtocolHandler::new(None);
        handler.toggle_block_number();
        let block = handler.build_rack().unwrap();

        assert_eq!(block.block_type(), BlockType::RBlock);
        assert_eq!(block.pcb.r_subtype, Some(RBlockSubtype::Ack));
        assert_eq!(block.block_number(), 1);
    }

    #[test]
    fn build_rnak_with_cid() {
        let handler = ProtocolHandler::new(Some(Cid::new(7).unwrap()));
        let block = handler.build_rnak().unwrap();

        assert_eq!(block.pcb.r_subtype, Some(RBlockSubtype::Nak));
        assert_eq!(block.cid.unwrap().value(), 7);
    }

    #[test]
    fn build_wtx_response_echoes_payload() {
        let handler = ProtocolHandler::new(None);
        let request = sblock_wtx(0x05);
        let response = handler.build_wtx_response(&request).unwrap();

        assert_eq!(response.block_type(), BlockType::SBlock);
        assert_eq!(response.pcb.s_subtype, Some(SBlockSubtype::Wtx));
        assert_eq!(response.payload.as_slice(), &[0x05]);
    }

    // ── Receive processing tests ────────────────────────────────────────

    #[test]
    fn receive_single_iblock() {
        let mut handler = ProtocolHandler::new(None);
        let block = iblock(0, &[0x01, 0x02, 0x03], false);

        match handler.process_received(block).unwrap() {
            Action::Complete(data) => assert_eq!(data.as_slice(), &[0x01, 0x02, 0x03]),
            other => panic!("expected Complete, got {:?}", other),
        }
        // Block number toggled
        assert_eq!(handler.block_number(), 1);
    }

    #[test]
    fn receive_chained_iblocks() {
        let mut handler = ProtocolHandler::new(None);

        // First chained I-Block
        let block1 = iblock(0, &[0x01, 0x02], true);
        match handler.process_received(block1).unwrap() {
            Action::Reply(reply) => {
                assert_eq!(reply.block_type(), BlockType::RBlock);
                assert_eq!(reply.pcb.r_subtype, Some(RBlockSubtype::Ack));
            }
            other => panic!("expected Reply(R(ACK)), got {:?}", other),
        }
        assert_eq!(handler.block_number(), 1);

        // Final I-Block
        let block2 = iblock(1, &[0x03, 0x04], false);
        match handler.process_received(block2).unwrap() {
            Action::Complete(data) => assert_eq!(data.as_slice(), &[0x01, 0x02, 0x03, 0x04]),
            other => panic!("expected Complete, got {:?}", other),
        }
    }

    #[test]
    fn receive_rack_matching_block_number() {
        let mut handler = ProtocolHandler::new(None);
        // block_number is 0, R(ACK) with 0 → ChainingAck, toggle to 1
        let block = rack(0);
        match handler.process_received(block).unwrap() {
            Action::ChainingAck => {}
            other => panic!("expected ChainingAck, got {:?}", other),
        }
        assert_eq!(handler.block_number(), 1);
    }

    #[test]
    fn receive_rack_wrong_block_number() {
        let mut handler = ProtocolHandler::new(None);
        // block_number is 0, R(ACK) with 1 → ChainingRetransmit
        let block = rack(1);
        match handler.process_received(block).unwrap() {
            Action::ChainingRetransmit => {}
            other => panic!("expected ChainingRetransmit, got {:?}", other),
        }
        // Block number unchanged
        assert_eq!(handler.block_number(), 0);
    }

    #[test]
    fn receive_rnak() {
        let mut handler = ProtocolHandler::new(None);
        let block = rnak(0);
        match handler.process_received(block).unwrap() {
            Action::ChainingRetransmit => {}
            other => panic!("expected ChainingRetransmit, got {:?}", other),
        }
    }

    #[test]
    fn receive_wtx_returns_reply() {
        let mut handler = ProtocolHandler::new(None);
        let block = sblock_wtx(0x03);
        match handler.process_received(block).unwrap() {
            Action::Reply(reply) => {
                assert_eq!(reply.block_type(), BlockType::SBlock);
                assert_eq!(reply.pcb.s_subtype, Some(SBlockSubtype::Wtx));
                assert_eq!(reply.payload.as_slice(), &[0x03]);
            }
            other => panic!("expected Reply(S(WTX)), got {:?}", other),
        }
    }

    #[test]
    fn receive_deselect_resets() {
        let mut handler = ProtocolHandler::new(None);
        handler.toggle_block_number(); // block_number = 1

        let block = sblock_deselect();
        match handler.process_received(block).unwrap() {
            Action::Reply(reply) => {
                assert_eq!(reply.block_type(), BlockType::SBlock);
                assert_eq!(reply.pcb.s_subtype, Some(SBlockSubtype::Deselect));
            }
            other => panic!("expected Reply(S(DESELECT)), got {:?}", other),
        }
        // Reset: block number back to 0, chain cleared
        assert_eq!(handler.block_number(), 0);
    }

    #[test]
    fn reset_clears_state() {
        let mut handler = ProtocolHandler::new(Some(Cid::new(5).unwrap()));
        handler.toggle_block_number();

        // Accumulate some chain data
        let _ = handler.process_received(iblock(1, &[0x01], true));

        handler.reset();
        assert_eq!(handler.block_number(), 0);

        // Chain is cleared — next single I-Block should return only its payload
        match handler.process_received(iblock(0, &[0xAA], false)).unwrap() {
            Action::Complete(data) => assert_eq!(data.as_slice(), &[0xAA]),
            other => panic!("expected Complete, got {:?}", other),
        }
    }
}
