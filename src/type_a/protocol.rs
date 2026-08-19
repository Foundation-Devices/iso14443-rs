// SPDX-FileCopyrightText: © 2025 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Generic ISO14443-4 block protocol handler.
//!
//! Role-agnostic: manages block numbering, block construction (with optional
//! CID), and chain accumulation. Returns [`Action`]s that the caller (PCD or
//! PICC transport layer) must execute.

use super::limits::{Counters, Limit, Limits};
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
///
/// The peer decides how many blocks an exchange takes, so the handler
/// counts them against its [`Limits`]: a card that answers every block with
/// R(NAK) or S(WTX), or chains payload without end, is cut off with
/// [`TypeAError::LimitExceeded`] rather than kept in the loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolHandler {
    cid: Option<Cid>,
    block_number: u8,
    chain: ChainVec,
    limits: Limits,
    counters: Counters,
}

impl ProtocolHandler {
    pub fn new(cid: Option<Cid>) -> Self {
        Self::with_limits(cid, Limits::default())
    }

    /// Create a handler with non-default work limits.
    pub fn with_limits(cid: Option<Cid>, limits: Limits) -> Self {
        Self {
            cid,
            block_number: 0,
            chain: ChainVec::new(),
            limits,
            counters: Counters::default(),
        }
    }

    /// The work limits applied to each exchange.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Replace the work limits. Takes effect on the next exchange.
    pub fn set_limits(&mut self, limits: Limits) {
        self.limits = limits;
    }

    pub fn block_number(&self) -> u8 {
        self.block_number
    }

    pub fn toggle_block_number(&mut self) {
        self.block_number = 1 - self.block_number;
    }

    pub fn reset(&mut self) {
        self.block_number = 0;
        self.begin_exchange();
    }

    /// Start an exchange: drop any accumulated chain and reset the
    /// per-exchange counters.
    pub fn begin_exchange(&mut self) {
        self.chain = ChainVec::new();
        self.counters.reset();
    }

    /// Count one frame received from the peer against the exchange's frame
    /// budget.
    ///
    /// [`ProtocolHandler::process_received`] does this itself; call it for
    /// frames answered outside the block layer, such as PPS, so they cannot
    /// be repeated indefinitely either.
    pub fn note_frame(&mut self) -> Result<(), TypeAError> {
        self.counters.frames = self.counters.frames.saturating_add(1);
        if self.counters.frames > self.limits.max_frames {
            return Err(self.exceeded(Limit::Frames));
        }
        Ok(())
    }

    /// Fail the exchange, leaving no accumulated payload behind.
    fn exceeded(&mut self, limit: Limit) -> TypeAError {
        self.chain = ChainVec::new();
        limit.into()
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
        self.note_frame()?;

        match block.block_type() {
            BlockType::IBlock => self.process_iblock(block),
            BlockType::RBlock => self.process_rblock(block),
            BlockType::SBlock => self.process_sblock(block),
        }
    }

    fn process_iblock(&mut self, block: Block) -> Result<Action, TypeAError> {
        if self.chain.len() + block.payload.len() > self.limits.max_chain_len {
            return Err(self.exceeded(Limit::ChainLength));
        }
        self.counters.note_progress();
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
                    self.counters.note_progress();
                    self.toggle_block_number();
                    Ok(Action::ChainingAck)
                } else {
                    self.note_retransmit()?;
                    Ok(Action::ChainingRetransmit)
                }
            }
            Some(RBlockSubtype::Nak) => {
                // NAK → caller should retransmit last block
                self.note_retransmit()?;
                Ok(Action::ChainingRetransmit)
            }
            None => Err(TypeAError::InvalidPcb),
        }
    }

    /// A retransmission request buys the peer nothing new; only so many in
    /// a row are tolerated.
    fn note_retransmit(&mut self) -> Result<(), TypeAError> {
        self.counters.retransmissions = self.counters.retransmissions.saturating_add(1);
        if self.counters.retransmissions > self.limits.max_retransmissions {
            return Err(self.exceeded(Limit::Retransmissions));
        }
        Ok(())
    }

    fn process_sblock(&mut self, block: Block) -> Result<Action, TypeAError> {
        match block.pcb.s_subtype {
            Some(SBlockSubtype::Wtx) => {
                self.check_wtx(&block)?;
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

    /// Validate an S(WTX) request and count it.
    ///
    /// §7.3: the INF field is one byte whose low six bits code a WTXM of 1
    /// to 59; 0 and 60 to 63 are RFU. A peer that keeps asking for more time
    /// without ever answering is stopped by the WTX counters.
    fn check_wtx(&mut self, block: &Block) -> Result<(), TypeAError> {
        let wtxm = match block.payload.as_slice() {
            [inf] => inf & 0x3f,
            _ => return Err(self.exceeded(Limit::WtxValue)),
        };
        if !(1..=59).contains(&wtxm) {
            return Err(self.exceeded(Limit::WtxValue));
        }

        self.counters.consecutive_wtx = self.counters.consecutive_wtx.saturating_add(1);
        if self.counters.consecutive_wtx > self.limits.max_consecutive_wtx {
            return Err(self.exceeded(Limit::ConsecutiveWtx));
        }

        self.counters.total_wtx = self.counters.total_wtx.saturating_add(1);
        if self.counters.total_wtx > self.limits.max_total_wtx {
            return Err(self.exceeded(Limit::TotalWtx));
        }

        Ok(())
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

    // ── Limit tests ─────────────────────────────────────────────────────

    /// Assert that a peer ran past the given limit.
    fn assert_limit(result: Result<Action, TypeAError>, limit: Limit) {
        match result {
            Err(TypeAError::LimitExceeded(hit)) if hit == limit => {}
            other => panic!("expected {:?}, got {:?}", limit, other),
        }
    }

    fn limited(limits: Limits) -> ProtocolHandler {
        ProtocolHandler::with_limits(None, limits)
    }

    #[test]
    fn nak_flood_terminates() {
        let mut handler = limited(Limits {
            max_retransmissions: 3,
            ..Limits::default()
        });

        // Three R(NAK) in a row are tolerated, the fourth is not
        for _ in 0..3 {
            assert!(matches!(
                handler.process_received(rnak(0)).unwrap(),
                Action::ChainingRetransmit
            ));
        }
        assert_limit(handler.process_received(rnak(0)), Limit::Retransmissions);
    }

    #[test]
    fn rack_with_wrong_block_number_counts_as_retransmission() {
        let mut handler = limited(Limits {
            max_retransmissions: 1,
            ..Limits::default()
        });

        // block_number is 0, so R(ACK) with 1 asks for a retransmission
        assert!(matches!(
            handler.process_received(rack(1)).unwrap(),
            Action::ChainingRetransmit
        ));
        assert_limit(handler.process_received(rack(1)), Limit::Retransmissions);
    }

    #[test]
    fn progress_clears_the_retransmission_count() {
        let mut handler = limited(Limits {
            max_retransmissions: 1,
            ..Limits::default()
        });

        let _ = handler.process_received(rnak(0)).unwrap();
        // A matching R(ACK) moves the exchange forward
        assert!(matches!(
            handler.process_received(rack(0)).unwrap(),
            Action::ChainingAck
        ));
        // ...so the peer gets its retransmission budget back
        assert!(matches!(
            handler.process_received(rnak(1)).unwrap(),
            Action::ChainingRetransmit
        ));
    }

    #[test]
    fn wtx_flood_terminates() {
        let mut handler = limited(Limits {
            max_consecutive_wtx: 2,
            ..Limits::default()
        });

        for _ in 0..2 {
            assert!(matches!(
                handler.process_received(sblock_wtx(0x01)).unwrap(),
                Action::Reply(_)
            ));
        }
        assert_limit(
            handler.process_received(sblock_wtx(0x01)),
            Limit::ConsecutiveWtx,
        );
    }

    #[test]
    fn total_wtx_is_bounded_even_when_interleaved() {
        let mut handler = limited(Limits {
            max_consecutive_wtx: 1,
            max_total_wtx: 2,
            ..Limits::default()
        });

        // Each S(WTX) is followed by a chained I-Block, so the consecutive
        // counter never trips — the per-exchange total still does.
        for _ in 0..2 {
            assert!(matches!(
                handler.process_received(sblock_wtx(0x01)).unwrap(),
                Action::Reply(_)
            ));
            assert!(matches!(
                handler.process_received(iblock(0, &[0xAA], true)).unwrap(),
                Action::Reply(_)
            ));
        }
        assert_limit(handler.process_received(sblock_wtx(0x01)), Limit::TotalWtx);
    }

    #[test]
    fn invalid_wtx_values_are_rejected() {
        let mut handler = ProtocolHandler::new(None);

        // WTXM is coded in the range 1 to 59; 0 and 60 to 63 are RFU
        assert_limit(handler.process_received(sblock_wtx(0x00)), Limit::WtxValue);
        assert_limit(handler.process_received(sblock_wtx(60)), Limit::WtxValue);
        // The power level bits are not part of WTXM
        assert!(matches!(
            handler.process_received(sblock_wtx(0xC1)).unwrap(),
            Action::Reply(_)
        ));

        // The INF field of an S(WTX) request is exactly one byte
        let empty_wtx = Block::new(Pcb::new(BlockType::SBlock).with_s_subtype(SBlockSubtype::Wtx));
        assert_limit(handler.process_received(empty_wtx), Limit::WtxValue);
    }

    #[test]
    fn chain_length_is_bounded() {
        let mut handler = limited(Limits {
            max_chain_len: 4,
            ..Limits::default()
        });

        assert!(matches!(
            handler.process_received(iblock(0, &[1, 2], true)).unwrap(),
            Action::Reply(_)
        ));
        assert!(matches!(
            handler.process_received(iblock(1, &[3, 4], true)).unwrap(),
            Action::Reply(_)
        ));
        assert_limit(
            handler.process_received(iblock(0, &[5], true)),
            Limit::ChainLength,
        );
    }

    #[test]
    fn frame_budget_is_bounded() {
        let mut handler = limited(Limits {
            max_frames: 2,
            ..Limits::default()
        });

        let _ = handler.process_received(iblock(0, &[1], true)).unwrap();
        let _ = handler.process_received(iblock(1, &[2], true)).unwrap();
        assert_limit(
            handler.process_received(iblock(0, &[3], true)),
            Limit::Frames,
        );

        // Frames answered outside the block layer count too
        let mut handler = limited(Limits {
            max_frames: 1,
            ..Limits::default()
        });
        handler.note_frame().unwrap();
        assert_eq!(
            handler.note_frame(),
            Err(TypeAError::LimitExceeded(Limit::Frames))
        );
    }

    #[test]
    fn limit_error_leaves_a_clean_handler() {
        let mut handler = limited(Limits {
            max_chain_len: 4,
            ..Limits::default()
        });

        let _ = handler
            .process_received(iblock(0, &[1, 2, 3, 4], true))
            .unwrap();
        assert_limit(
            handler.process_received(iblock(1, &[5], true)),
            Limit::ChainLength,
        );

        // The accumulated payload is dropped, and the next exchange starts
        // from a clean slate rather than inheriting counters or bytes.
        handler.begin_exchange();
        match handler.process_received(iblock(0, &[0xAA], false)).unwrap() {
            Action::Complete(data) => assert_eq!(data.as_slice(), &[0xAA]),
            other => panic!("expected Complete, got {:?}", other),
        }
    }
}
