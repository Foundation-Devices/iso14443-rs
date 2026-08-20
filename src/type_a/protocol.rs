// SPDX-FileCopyrightText: © 2025 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Generic ISO14443-4 block protocol handler.
//!
//! Manages block numbering, block construction (with optional CID), and
//! chain accumulation. Returns [`Action`]s that the caller (PCD or PICC
//! transport layer) must execute.
//!
//! The two sides of the link do not follow the same numbering rules, so a
//! handler is built for a [`Role`] and applies that role's rules. See
//! [`Role`] for the rules and §7.5.3 of ISO/IEC 14443-4 for their wording.

use super::limits::{Counters, Limit, Limits};
use super::pcb::Pcb;
use super::vec::{ChainVec, FrameVec, VecExt};
use super::{Block, BlockType, Cid, RBlockSubtype, SBlockSubtype, TypeAError};

/// Which side of the link a [`ProtocolHandler`] drives.
///
/// ISO14443-4 §7.5.3 gives the two roles mirrored block numbering rules,
/// and §7.5.4 mirrored R-block rules. Picking the wrong one does not fail
/// loudly — it desynchronises the numbering, which makes the peer
/// retransmit blocks that then get appended to the payload a second time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Reader. Block number starts at 0 (Rule A) and toggles when an
    /// I-Block or an R(ACK) carrying the current number is received
    /// (Rule B). An R(ACK) that matches continues chaining (Rule 7), one
    /// that does not asks for the last I-Block again (Rule 6).
    Pcd,
    /// Card. Block number starts at 1 (Rule C), toggles on every I-Block
    /// received (Rule D) and on an R(ACK) carrying a different number
    /// (Rule E). An R-block that matches asks for the last block again
    /// (Rule 11); an R(ACK) that does not continues chaining (Rule 13).
    Picc,
}

impl Role {
    /// The block number the role starts an activation with: Rule A for the
    /// PCD, Rule C for the PICC.
    fn initial_block_number(self) -> u8 {
        match self {
            Role::Pcd => 0,
            Role::Picc => 1,
        }
    }
}

/// Action the caller must take after processing a received block.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // ChainVec is large in no_std (heapless); boxing requires alloc
pub enum Action {
    /// The received I-Block completes the exchange (single block or final
    /// block of a chain). The assembled payload is returned.
    Complete(ChainVec),
    /// The caller must send this block to continue the protocol:
    /// R(ACK) during chaining or for a repeated block, S(WTX) echo, or
    /// S(DESELECT) echo.
    Reply(Block),
    /// The peer took the last block; the caller should send the next
    /// chained I-Block.
    ChainingAck,
    /// The peer is asking for the last block again; the caller should
    /// retransmit it.
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
    role: Role,
    cid: Option<Cid>,
    block_number: u8,
    chain: ChainVec,
    limits: Limits,
    counters: Counters,
}

impl ProtocolHandler {
    pub fn new(role: Role, cid: Option<Cid>) -> Self {
        Self::with_limits(role, cid, Limits::default())
    }

    /// Create a handler with non-default work limits.
    pub fn with_limits(role: Role, cid: Option<Cid>, limits: Limits) -> Self {
        Self {
            role,
            cid,
            block_number: role.initial_block_number(),
            chain: ChainVec::new(),
            limits,
            counters: Counters::default(),
        }
    }

    /// The side of the link this handler drives.
    pub fn role(&self) -> Role {
        self.role
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

    /// Toggle the block number.
    ///
    /// Private: the numbering rules say *when* to toggle, and the handler
    /// applies them itself as blocks are received. A caller toggling on its
    /// own is how the two roles drift apart.
    fn toggle_block_number(&mut self) {
        self.block_number = 1 - self.block_number;
    }

    /// Return to the state of a freshly activated peer: Rule A for the PCD,
    /// Rule C for the PICC.
    pub fn reset(&mut self) {
        self.block_number = self.role.initial_block_number();
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
        if self.repeats_last_iblock(&block) {
            // The peer sent this block once already and we took its payload
            // in. Appending it again would silently corrupt the assembled
            // APDU, so acknowledge it once more — the same R(ACK) it missed
            // — and leave the block number where it is. The retransmission
            // budget bounds a peer that keeps repeating itself.
            self.note_retransmit()?;
            return Ok(Action::Reply(self.build_rack()?));
        }

        if self.chain.len() + block.payload.len() > self.limits.max_chain_len {
            return Err(self.exceeded(Limit::ChainLength));
        }
        self.counters.note_progress();
        self.chain.try_extend(block.payload.as_slice())?;

        // Rules B and D: toggle on reception, so whatever goes out next —
        // the R(ACK) below, or the response I-Block the caller builds after
        // Complete — already carries the new number.
        self.toggle_block_number();

        if block.is_chaining() {
            Ok(Action::Reply(self.build_rack()?))
        } else {
            let mut data = ChainVec::new();
            core::mem::swap(&mut data, &mut self.chain);
            Ok(Action::Complete(data))
        }
    }

    /// Is this I-Block a repeat of the one we last took in?
    ///
    /// In step, a PCD gets its own block number back — that is what Rule B
    /// means by "equal to the current block number" — while a PICC gets the
    /// opposite one, Rule D having already toggled its own away. Either
    /// role seeing the other case is looking at a block it has processed.
    fn repeats_last_iblock(&self, block: &Block) -> bool {
        match self.role {
            Role::Pcd => block.block_number() != self.block_number,
            Role::Picc => block.block_number() == self.block_number,
        }
    }

    fn process_rblock(&mut self, block: Block) -> Result<Action, TypeAError> {
        let matches_ours = block.block_number() == self.block_number;

        match (self.role, block.pcb.r_subtype) {
            // Rule 7: an R(ACK) carrying the PCD's own block number
            // acknowledges the last chunk, so chaining continues (Rule B
            // toggles first). Rule 6: any other number asks for it again.
            (Role::Pcd, Some(RBlockSubtype::Ack)) if matches_ours => {
                self.counters.note_progress();
                self.toggle_block_number();
                Ok(Action::ChainingAck)
            }
            // §7.5.4.3 note: a PICC never sends R(NAK). Treated like a
            // mismatched R(ACK) — retransmit, bounded by the budget.
            (Role::Pcd, Some(_)) => {
                self.note_retransmit()?;
                Ok(Action::ChainingRetransmit)
            }
            // Rule 11: an R(ACK) or R(NAK) carrying the PICC's own block
            // number means the PCD did not get the last block.
            (Role::Picc, Some(_)) if matches_ours => {
                self.note_retransmit()?;
                Ok(Action::ChainingRetransmit)
            }
            // Rules E and 13: a different number acknowledges the last
            // chunk, so the PICC toggles and carries on chaining.
            (Role::Picc, Some(RBlockSubtype::Ack)) => {
                self.counters.note_progress();
                self.toggle_block_number();
                Ok(Action::ChainingAck)
            }
            // Rule 12: an out-of-step R(NAK) is answered with an R(ACK).
            (Role::Picc, Some(RBlockSubtype::Nak)) => {
                self.note_retransmit()?;
                Ok(Action::Reply(self.build_rack()?))
            }
            (_, None) => Err(TypeAError::InvalidPcb),
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
        // Rule 1: the first block is the PCD's, so that is the side a
        // handler defaults to.
        Self::new(Role::Pcd, None)
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

    fn pcd() -> ProtocolHandler {
        ProtocolHandler::new(Role::Pcd, None)
    }

    fn picc() -> ProtocolHandler {
        ProtocolHandler::new(Role::Picc, None)
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
        let handler = ProtocolHandler::new(Role::Pcd, Some(Cid::new(3).unwrap()));
        let block = handler.build_iblock(&[0x01, 0x02], false).unwrap();

        assert_eq!(block.block_type(), BlockType::IBlock);
        assert_eq!(block.block_number(), 0);
        assert!(!block.is_chaining());
        assert_eq!(block.cid.unwrap().value(), 3);
        assert_eq!(block.payload.as_slice(), &[0x01, 0x02]);
    }

    #[test]
    fn build_iblock_without_cid() {
        let handler = pcd();
        let block = handler.build_iblock(&[0xAA], true).unwrap();

        assert!(block.cid.is_none());
        assert!(block.is_chaining());
    }

    #[test]
    fn build_rack_with_correct_block_number() {
        let mut handler = pcd();
        handler.toggle_block_number();
        let block = handler.build_rack().unwrap();

        assert_eq!(block.block_type(), BlockType::RBlock);
        assert_eq!(block.pcb.r_subtype, Some(RBlockSubtype::Ack));
        assert_eq!(block.block_number(), 1);
    }

    #[test]
    fn build_rnak_with_cid() {
        let handler = ProtocolHandler::new(Role::Pcd, Some(Cid::new(7).unwrap()));
        let block = handler.build_rnak().unwrap();

        assert_eq!(block.pcb.r_subtype, Some(RBlockSubtype::Nak));
        assert_eq!(block.cid.unwrap().value(), 7);
    }

    #[test]
    fn build_wtx_response_echoes_payload() {
        let handler = pcd();
        let request = sblock_wtx(0x05);
        let response = handler.build_wtx_response(&request).unwrap();

        assert_eq!(response.block_type(), BlockType::SBlock);
        assert_eq!(response.pcb.s_subtype, Some(SBlockSubtype::Wtx));
        assert_eq!(response.payload.as_slice(), &[0x05]);
    }

    // ── Receive processing tests ────────────────────────────────────────

    #[test]
    fn receive_single_iblock() {
        let mut handler = pcd();
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
        let mut handler = pcd();

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
        let mut handler = pcd();
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
        let mut handler = pcd();
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
        let mut handler = pcd();
        let block = rnak(0);
        match handler.process_received(block).unwrap() {
            Action::ChainingRetransmit => {}
            other => panic!("expected ChainingRetransmit, got {:?}", other),
        }
    }

    #[test]
    fn receive_wtx_returns_reply() {
        let mut handler = pcd();
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
        let mut handler = pcd();
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
        let mut handler = ProtocolHandler::new(Role::Pcd, Some(Cid::new(5).unwrap()));
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

    // ── Role rules (§7.5.3 numbering, §7.5.4 block handling) ────────────

    /// Unwrap an [`Action::Reply`] carrying an R(ACK), returning its number.
    fn rack_number(action: Action) -> u8 {
        match action {
            Action::Reply(reply) => {
                assert_eq!(reply.block_type(), BlockType::RBlock);
                assert_eq!(reply.pcb.r_subtype, Some(RBlockSubtype::Ack));
                reply.block_number()
            }
            other => panic!("expected Reply(R(ACK)), got {:?}", other),
        }
    }

    #[test]
    fn block_numbers_start_where_the_rules_say() {
        assert_eq!(pcd().block_number(), 0); // Rule A
        assert_eq!(picc().block_number(), 1); // Rule C
    }

    #[test]
    fn pcd_acks_a_chained_iblock_with_the_toggled_number() {
        // Rule B: the PCD toggles when it takes the I-Block in, so the
        // R(ACK) that follows carries the *new* number. Echoing the
        // received number back instead makes a conformant card read its own
        // number (Rule 11) and repeat the chunk it just sent.
        let mut handler = pcd();
        let action = handler
            .process_received(iblock(0, &[0x01, 0x02], true))
            .unwrap();

        assert_eq!(rack_number(action), 1);
        assert_eq!(handler.block_number(), 1);
    }

    #[test]
    fn picc_acks_a_chained_iblock_with_the_toggled_number() {
        // Rule D: the card toggles on any I-Block it receives, which lands
        // its number on the one the reader is using.
        let mut handler = picc();
        let action = handler
            .process_received(iblock(0, &[0x01, 0x02], true))
            .unwrap();

        assert_eq!(rack_number(action), 0);
        assert_eq!(handler.block_number(), 0);
    }

    #[test]
    fn pcd_assembles_a_chained_response_once() {
        // The whole sequence a card in step produces, with the R(ACK)
        // numbers the reader is expected to answer with.
        let mut handler = pcd();

        assert_eq!(
            rack_number(handler.process_received(iblock(0, &[1, 2], true)).unwrap()),
            1
        );
        assert_eq!(
            rack_number(handler.process_received(iblock(1, &[3, 4], true)).unwrap()),
            0
        );
        match handler.process_received(iblock(0, &[5, 6], false)).unwrap() {
            Action::Complete(data) => assert_eq!(data.as_slice(), &[1, 2, 3, 4, 5, 6]),
            other => panic!("expected Complete, got {:?}", other),
        }
        // Three I-Blocks in, so the next command goes out numbered 1
        assert_eq!(handler.block_number(), 1);
    }

    #[test]
    fn pcd_drops_a_repeated_iblock() {
        // A card that repeats a chunk — because it missed the R(ACK), or
        // because it is trying to inflate the response — must not have that
        // payload counted twice.
        let mut handler = pcd();
        let action = handler.process_received(iblock(0, &[1, 2], true)).unwrap();
        assert_eq!(rack_number(action), 1);

        // Same chunk again: the number no longer matches ours (Rule B)
        let action = handler.process_received(iblock(0, &[1, 2], true)).unwrap();
        assert_eq!(rack_number(action), 1, "the R(ACK) is simply repeated");
        assert_eq!(handler.block_number(), 1, "and the number stands still");

        match handler.process_received(iblock(1, &[3, 4], false)).unwrap() {
            Action::Complete(data) => assert_eq!(data.as_slice(), &[1, 2, 3, 4]),
            other => panic!("expected Complete, got {:?}", other),
        }
    }

    #[test]
    fn picc_drops_a_repeated_iblock() {
        // Mirror image: Rule D has already toggled the card's number away
        // from the block it took in, so a block carrying that number again
        // is one it has seen.
        let mut handler = picc();
        assert_eq!(
            rack_number(handler.process_received(iblock(0, &[1, 2], true)).unwrap()),
            0
        );
        assert_eq!(
            rack_number(handler.process_received(iblock(0, &[1, 2], true)).unwrap()),
            0
        );
        assert_eq!(handler.block_number(), 0);

        match handler.process_received(iblock(1, &[3, 4], false)).unwrap() {
            Action::Complete(data) => assert_eq!(data.as_slice(), &[1, 2, 3, 4]),
            other => panic!("expected Complete, got {:?}", other),
        }
    }

    #[test]
    fn a_repeating_peer_runs_out_of_budget() {
        let mut handler = limited(Limits {
            max_retransmissions: 2,
            ..Limits::default()
        });

        assert_eq!(
            rack_number(handler.process_received(iblock(0, &[1, 2], true)).unwrap()),
            1
        );
        for _ in 0..2 {
            let action = handler.process_received(iblock(0, &[1, 2], true)).unwrap();
            assert_eq!(rack_number(action), 1);
        }
        assert_limit(
            handler.process_received(iblock(0, &[1, 2], true)),
            Limit::Retransmissions,
        );
    }

    #[test]
    fn picc_continues_chaining_on_a_differing_rack() {
        // Rules E and 13: the reader acknowledged the last chunk with its
        // own number, which is not the card's.
        let mut handler = picc(); // block number 1
        match handler.process_received(rack(0)).unwrap() {
            Action::ChainingAck => {}
            other => panic!("expected ChainingAck, got {:?}", other),
        }
        assert_eq!(handler.block_number(), 0);
    }

    #[test]
    fn picc_repeats_its_block_on_a_matching_rack() {
        // Rule 11: the reader is asking for the last block again.
        let mut handler = picc(); // block number 1
        match handler.process_received(rack(1)).unwrap() {
            Action::ChainingRetransmit => {}
            other => panic!("expected ChainingRetransmit, got {:?}", other),
        }
        assert_eq!(handler.block_number(), 1);
    }

    #[test]
    fn picc_repeats_its_block_on_a_matching_rnak() {
        // Rule 11 again — R(NAK) with the card's own number.
        let mut handler = picc();
        match handler.process_received(rnak(1)).unwrap() {
            Action::ChainingRetransmit => {}
            other => panic!("expected ChainingRetransmit, got {:?}", other),
        }
        assert_eq!(handler.block_number(), 1);
    }

    #[test]
    fn picc_answers_an_out_of_step_rnak_with_an_rack() {
        // Rule 12: R(NAK) carrying a different number is answered by an
        // R(ACK), and does not move the card's number (only Rule E does).
        let mut handler = picc();
        assert_eq!(rack_number(handler.process_received(rnak(0)).unwrap()), 1);
        assert_eq!(handler.block_number(), 1);
    }

    #[test]
    fn deselect_returns_each_role_to_its_starting_number() {
        let mut handler = pcd();
        let _ = handler.process_received(iblock(0, &[0xAA], false)).unwrap();
        let _ = handler.process_received(sblock_deselect()).unwrap();
        assert_eq!(handler.block_number(), 0);

        let mut handler = picc();
        let _ = handler.process_received(iblock(0, &[0xAA], false)).unwrap();
        let _ = handler.process_received(sblock_deselect()).unwrap();
        assert_eq!(handler.block_number(), 1);
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
        ProtocolHandler::with_limits(Role::Pcd, None, limits)
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
        for block_number in [0, 1] {
            assert!(matches!(
                handler.process_received(sblock_wtx(0x01)).unwrap(),
                Action::Reply(_)
            ));
            assert!(matches!(
                handler
                    .process_received(iblock(block_number, &[0xAA], true))
                    .unwrap(),
                Action::Reply(_)
            ));
        }
        assert_limit(handler.process_received(sblock_wtx(0x01)), Limit::TotalWtx);
    }

    #[test]
    fn invalid_wtx_values_are_rejected() {
        let mut handler = pcd();

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
        // from a clean slate rather than inheriting counters or bytes. The
        // block number survives the failed exchange — it belongs to the
        // activation — so the next answer carries the number it left on.
        handler.begin_exchange();
        assert_eq!(handler.block_number(), 1);
        match handler.process_received(iblock(1, &[0xAA], false)).unwrap() {
            Action::Complete(data) => assert_eq!(data.as_slice(), &[0xAA]),
            other => panic!("expected Complete, got {:?}", other),
        }
    }
}
