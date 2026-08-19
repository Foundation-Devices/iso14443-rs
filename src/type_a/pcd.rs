// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! ISO14443-4 PCD (reader) transport layer.
//!
//! Drives the half-duplex block protocol on top of a [`PcdTransceiver`]:
//! RATS/ATS negotiation, optional PPS, APDU exchange with chaining in both
//! directions, WTX handling, error recovery, and DESELECT.

use super::{
    Block, Cid, Frame, PcdTransceiver, TypeAError,
    ats::Ats,
    crc::append_crc_a,
    limits::{Limit, Limits},
    pcb::{BlockType, SBlockSubtype},
    pps::{Dxi, PpsParam, PpsResp},
    protocol::{Action, ProtocolHandler},
    rats::{Fsdi, RatsParam},
    vec::{ChainVec, FrameVec, VecExt},
};

const MAX_RETRIES: u8 = 2;

/// Error during PCD protocol operations.
#[derive(Debug)]
pub enum PcdError<E> {
    /// The transceiver returned an error.
    PcdTransceiver(E),
    /// ISO14443 protocol violation.
    Protocol(TypeAError),
}

impl<E> From<TypeAError> for PcdError<E> {
    fn from(e: TypeAError) -> Self {
        PcdError::Protocol(e)
    }
}

/// ISO14443-4 PCD session.
///
/// Tracks protocol state for a single activated PICC: CRC strategy,
/// negotiated frame size, and the generic block protocol handler.
#[derive(Debug)]
pub struct Pcd<'t, T: PcdTransceiver> {
    transceiver: &'t mut T,
    hw_crc: bool,
    /// Maximum frame size the PICC accepts (from ATS FSCI).
    fsc: usize,
    /// Maximum frame size we told the PICC we accept (from RATS FSDI).
    fsd: usize,
    handler: ProtocolHandler,
}

impl<'t, T: PcdTransceiver> Pcd<'t, T> {
    /// Full setup: probe hardware CRC, send RATS, parse ATS, return a
    /// ready session and the parsed ATS for inspection.
    pub fn connect(t: &'t mut T, fsdi: Fsdi, cid: Cid) -> Result<(Self, Ats), PcdError<T::Error>> {
        let hw_crc = t.try_enable_hw_crc().is_ok();

        // Build and send RATS
        let rats = RatsParam::new(fsdi, cid);
        let rats_byte = u8::from(&rats);
        let data = if hw_crc {
            let mut v = FrameVec::new();
            v.try_push(0xe0)?;
            v.try_push(rats_byte)?;
            v
        } else {
            append_crc_a(&[0xe0, rats_byte])?
        };

        let resp = t
            .transceive(&Frame::Standard(data))
            .map_err(PcdError::PcdTransceiver)?;

        // Parse ATS — the transceiver already checked and stripped the CRC
        // in the hardware-CRC path
        let ats = if hw_crc {
            Ats::from_crc_verified(resp.as_slice())?
        } else {
            Ats::try_from(resp.as_slice())?
        };

        let fsc = ats.format.fsci.fsc();

        Ok((
            Self {
                transceiver: t,
                hw_crc,
                fsc,
                fsd: fsdi.fsd(),
                handler: ProtocolHandler::new(Some(cid)),
            },
            ats,
        ))
    }

    /// Manual setup for callers who have already handled RATS/ATS
    /// externally (e.g. via the CLI parser).
    ///
    /// `fsdi` must be the frame size the RATS announced, since responses
    /// larger than that FSD are rejected.
    pub fn new(
        transceiver: &'t mut T,
        ats: &Ats,
        fsdi: Fsdi,
        cid: Option<Cid>,
        hw_crc: bool,
    ) -> Self {
        Self {
            transceiver,
            hw_crc,
            fsc: ats.format.fsci.fsc(),
            fsd: fsdi.fsd(),
            handler: ProtocolHandler::new(cid),
        }
    }

    /// The work limits applied to each exchange.
    pub fn limits(&self) -> &Limits {
        self.handler.limits()
    }

    /// Replace the work limits. Takes effect on the next exchange.
    pub fn set_limits(&mut self, limits: Limits) {
        self.handler.set_limits(limits);
    }

    /// Negotiate bit rates via PPS (optional, call after connect/new).
    pub fn pps(&mut self, dri: Dxi, dsi: Dxi) -> Result<(), PcdError<T::Error>> {
        let cid = self
            .handler
            .build_rack()
            .ok()
            .and_then(|b| b.cid)
            .unwrap_or_else(|| Cid::new(0).unwrap());
        let param = PpsParam { cid, dri, dsi };
        let pps1 = u8::from(&param);
        let cid_byte = 0xd0 + u8::from(&cid);

        let data = if self.hw_crc {
            let mut v = FrameVec::new();
            v.try_push(cid_byte)?;
            v.try_push(0x11)?;
            v.try_push(pps1)?;
            v
        } else {
            append_crc_a(&[cid_byte, 0x11, pps1])?
        };

        let resp = self
            .transceiver
            .transceive(&Frame::Standard(data))
            .map_err(PcdError::PcdTransceiver)?;

        // Validate PPS response
        if self.hw_crc {
            let _ = PpsResp::from_crc_verified(resp.as_slice())?;
        } else {
            let _ = PpsResp::try_from(resp.as_slice())?;
        };

        Ok(())
    }

    /// Exchange an APDU: send command bytes, receive response bytes.
    ///
    /// Handles chaining in both directions, S(WTX) responses, and error
    /// recovery per ISO14443-4 §7.5.
    pub fn exchange(&mut self, apdu: &[u8]) -> Result<ChainVec, PcdError<T::Error>> {
        self.handler.begin_exchange();

        // Max payload per I-Block: FSC minus prologue (PCB + optional CID)
        // minus epilogue (2-byte CRC).
        let cid_len = if self.handler.build_iblock(&[], false)?.cid.is_some() {
            1
        } else {
            0
        };
        let overhead = 1 + cid_len + 2;
        let max_inf = self.fsc.saturating_sub(overhead);
        if max_inf == 0 {
            return Err(PcdError::Protocol(TypeAError::Other));
        }

        let mut offset = 0;
        let mut last_resp: Option<Block> = None;

        // --- PCD-side chaining (send APDU) ---
        while offset < apdu.len() {
            let end = core::cmp::min(offset + max_inf, apdu.len());
            let chaining = end < apdu.len();
            let iblock = self.handler.build_iblock(&apdu[offset..end], chaining)?;

            let resp = self.transceive_block(&iblock)?;

            if chaining {
                match self.handler.process_received(resp)? {
                    Action::ChainingAck => {
                        offset = end;
                    }
                    Action::ChainingRetransmit => {
                        // Retransmit same chunk (don't advance offset)
                        continue;
                    }
                    _ => return Err(PcdError::Protocol(TypeAError::Other)),
                }
            } else {
                self.handler.toggle_block_number();
                last_resp = Some(resp);
                offset = end;
            }
        }

        // --- PICC-side chaining (receive response) ---
        let first = last_resp.ok_or(PcdError::Protocol(TypeAError::Other))?;
        self.collect_response(first)
    }

    /// Send S(DESELECT), wait for response. Retries once per Rule 8.
    pub fn deselect(&mut self) -> Result<(), PcdError<T::Error>> {
        let deselect = self.handler.build_sblock(SBlockSubtype::Deselect)?;

        match self.transceive_block(&deselect) {
            Ok(ref resp)
                if resp.block_type() == BlockType::SBlock
                    && resp.pcb.s_subtype == Some(SBlockSubtype::Deselect) =>
            {
                Ok(())
            }
            _ => {
                // Rule 8: retry once
                let resp = self.transceive_block(&deselect)?;
                if resp.block_type() == BlockType::SBlock
                    && resp.pcb.s_subtype == Some(SBlockSubtype::Deselect)
                {
                    Ok(())
                } else {
                    Err(PcdError::Protocol(TypeAError::Other))
                }
            }
        }
    }

    // ── Private helpers ─────────────────────────────────────────────────

    /// Collect the full PICC response, handling chaining, WTX, and errors.
    fn collect_response(&mut self, first: Block) -> Result<ChainVec, PcdError<T::Error>> {
        let mut block = first;

        loop {
            match self.handler.process_received(block)? {
                Action::Complete(data) => return Ok(data),
                Action::Reply(reply) => {
                    block = self.transceive_with_recovery(&reply, true)?;
                }
                _ => return Err(PcdError::Protocol(TypeAError::Other)),
            }
        }
    }

    /// Transceive with error recovery per §7.5.5.
    ///
    /// On transceiver error or parse failure:
    /// - `receiving_chain = true` → send R(ACK) (Rule 5)
    /// - `receiving_chain = false` → send R(NAK) (Rule 4)
    fn transceive_with_recovery(
        &mut self,
        block: &Block,
        receiving_chain: bool,
    ) -> Result<Block, PcdError<T::Error>> {
        match self.transceive_block(block) {
            Ok(resp) => Ok(resp),
            Err(_) => {
                let mut retries = 0;
                loop {
                    if retries >= MAX_RETRIES {
                        return Err(PcdError::Protocol(TypeAError::Other));
                    }
                    retries += 1;

                    let recovery = if receiving_chain {
                        self.handler.build_rack()?
                    } else {
                        self.handler.build_rnak()?
                    };

                    match self.transceive_block(&recovery) {
                        Ok(resp) => return Ok(resp),
                        Err(_) => continue,
                    }
                }
            }
        }
    }

    /// Send a block via the transceiver and parse the response.
    fn transceive_block(&mut self, block: &Block) -> Result<Block, PcdError<T::Error>> {
        let data = block.to_bytes_without_crc()?;
        let frame = if self.hw_crc {
            Frame::Standard(data)
        } else {
            Frame::Standard(append_crc_a(&data)?)
        };

        let resp = self
            .transceiver
            .transceive(&frame)
            .map_err(PcdError::PcdTransceiver)?;

        self.parse_block_response(&resp)
    }

    /// Parse a raw response into a Block, handling the CRC strategy.
    ///
    /// The RATS told the PICC how large a frame we accept; anything longer
    /// is refused before it is parsed or accumulated.
    fn parse_block_response(&self, raw: &[u8]) -> Result<Block, PcdError<T::Error>> {
        if self.hw_crc {
            // The transceiver already validated the CRC and stripped it, so
            // the frame was two bytes longer on the air
            if raw.len() + 2 > self.fsd {
                return Err(PcdError::Protocol(Limit::FrameSize.into()));
            }
            Ok(Block::from_crc_verified(raw)?)
        } else {
            if raw.len() > self.fsd {
                return Err(PcdError::Protocol(Limit::FrameSize.into()));
            }
            Ok(Block::try_from(raw)?)
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    use super::super::pcb::{Pcb, RBlockSubtype};
    use super::super::vec::VecExt;
    use super::*;

    // ── Mock transceiver ────────────────────────────────────────────────

    #[derive(Debug)]
    struct MockError;

    struct MockTransceiver {
        hw_crc: bool,
        responses: Vec<FrameVec>,
        sent: Vec<FrameVec>,
        call_idx: usize,
    }

    impl MockTransceiver {
        fn new(hw_crc: bool, responses: Vec<FrameVec>) -> Self {
            Self {
                hw_crc,
                responses,
                sent: Vec::new(),
                call_idx: 0,
            }
        }
    }

    impl PcdTransceiver for MockTransceiver {
        type Error = MockError;

        fn transceive(&mut self, frame: &Frame) -> Result<FrameVec, MockError> {
            let mut copy = FrameVec::new();
            let _ = copy.try_extend(frame.data());
            self.sent.push(copy);

            if self.call_idx < self.responses.len() {
                let resp = self.responses[self.call_idx].clone();
                self.call_idx += 1;
                Ok(resp)
            } else {
                Err(MockError)
            }
        }

        fn try_enable_hw_crc(&mut self) -> Result<(), MockError> {
            if self.hw_crc { Ok(()) } else { Err(MockError) }
        }
    }

    fn frame_vec(data: &[u8]) -> FrameVec {
        let mut v = FrameVec::new();
        v.try_extend(data).unwrap();
        v
    }

    fn mock_iblock_response(block_number: u8, payload: &[u8], chaining: bool) -> FrameVec {
        let pcb = Pcb::new(BlockType::IBlock)
            .with_block_number(block_number)
            .with_chaining(chaining);
        Block::new(pcb)
            .with_payload(frame_vec(payload))
            .to_vec()
            .unwrap()
    }

    fn mock_rack_response(block_number: u8) -> FrameVec {
        let pcb = Pcb::new(BlockType::RBlock)
            .with_block_number(block_number)
            .with_r_subtype(RBlockSubtype::Ack);
        Block::new(pcb).to_vec().unwrap()
    }

    fn mock_wtx_request(wtxm: u8) -> FrameVec {
        let pcb = Pcb::new(BlockType::SBlock).with_s_subtype(SBlockSubtype::Wtx);
        Block::new(pcb)
            .with_payload(frame_vec(&[wtxm]))
            .to_vec()
            .unwrap()
    }

    fn mock_deselect_response() -> FrameVec {
        let pcb = Pcb::new(BlockType::SBlock).with_s_subtype(SBlockSubtype::Deselect);
        Block::new(pcb).to_vec().unwrap()
    }

    fn minimal_ats() -> Ats {
        let raw = append_crc_a(&[0x05, 0x78, 0x80, 0x40, 0x02]).unwrap();
        Ats::try_from(raw.as_slice()).unwrap()
    }

    fn small_fsc_ats() -> Ats {
        let raw = append_crc_a(&[0x05, 0x70, 0x80, 0x40, 0x02]).unwrap();
        Ats::try_from(raw.as_slice()).unwrap()
    }

    // ── Tests ───────────────────────────────────────────────────────────

    #[test]
    fn single_iblock_exchange() {
        let resp = mock_iblock_response(0, &[0xAA, 0xBB], false);
        let mut t = MockTransceiver::new(false, vec![resp]);
        let ats = minimal_ats();

        let mut pcd = Pcd::new(&mut t, &ats, Fsdi::Fsd256, None, false);
        let result = pcd.exchange(&[0x01, 0x02]).unwrap();

        assert_eq!(result.as_slice(), &[0xAA, 0xBB]);
    }

    #[test]
    fn pcd_side_chaining() {
        // FSC=16, overhead=3 (PCB + CRC×2, no CID), max_inf=13
        // Send 20 bytes → 2 chunks: 13 + 7
        let ack = mock_rack_response(0);
        let resp = mock_iblock_response(0, &[0xFF], false);
        let mut t = MockTransceiver::new(false, vec![ack, resp]);
        let ats = small_fsc_ats();

        let mut pcd = Pcd::new(&mut t, &ats, Fsdi::Fsd256, None, false);
        let result = pcd.exchange(&[0x42u8; 20]).unwrap();

        assert_eq!(result.as_slice(), &[0xFF]);
        assert_eq!(t.sent.len(), 2);
    }

    #[test]
    fn picc_side_chaining() {
        let resp1 = mock_iblock_response(0, &[0x01, 0x02], true);
        let resp2 = mock_iblock_response(1, &[0x03, 0x04], false);
        let mut t = MockTransceiver::new(false, vec![resp1, resp2]);
        let ats = minimal_ats();

        let mut pcd = Pcd::new(&mut t, &ats, Fsdi::Fsd256, None, false);
        let result = pcd.exchange(&[0xAA]).unwrap();

        assert_eq!(result.as_slice(), &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(t.sent.len(), 2);
    }

    #[test]
    fn wtx_handling() {
        let wtx = mock_wtx_request(0x01);
        let resp = mock_iblock_response(0, &[0xCC], false);
        let mut t = MockTransceiver::new(false, vec![wtx, resp]);
        let ats = minimal_ats();

        let mut pcd = Pcd::new(&mut t, &ats, Fsdi::Fsd256, None, false);
        let result = pcd.exchange(&[0x01]).unwrap();

        assert_eq!(result.as_slice(), &[0xCC]);
        assert_eq!(t.sent.len(), 2);
    }

    #[test]
    fn deselect_ok() {
        let resp = mock_deselect_response();
        let mut t = MockTransceiver::new(false, vec![resp]);
        let ats = minimal_ats();

        let mut pcd = Pcd::new(&mut t, &ats, Fsdi::Fsd256, None, false);
        pcd.deselect().unwrap();
    }

    #[test]
    fn deselect_retry() {
        let bad_resp = mock_rack_response(0);
        let good_resp = mock_deselect_response();
        let mut t = MockTransceiver::new(false, vec![bad_resp, good_resp]);
        let ats = minimal_ats();

        let mut pcd = Pcd::new(&mut t, &ats, Fsdi::Fsd256, None, false);
        pcd.deselect().unwrap();
        assert_eq!(t.sent.len(), 2);
    }

    #[test]
    fn hw_crc_single_exchange() {
        let pcb = Pcb::new(BlockType::IBlock).with_block_number(0);
        let block = Block::new(pcb).with_payload(frame_vec(&[0xDE, 0xAD]));
        let raw_no_crc = block.to_bytes_without_crc().unwrap();

        let mut t = MockTransceiver::new(true, vec![raw_no_crc]);
        let ats = minimal_ats();

        let mut pcd = Pcd::new(&mut t, &ats, Fsdi::Fsd256, None, true);
        let result = pcd.exchange(&[0x01]).unwrap();

        assert_eq!(result.as_slice(), &[0xDE, 0xAD]);
        let sent = &t.sent[0];
        assert_eq!(sent.len(), 2); // PCB + payload, no CRC
    }

    #[test]
    fn connect_rejects_malformed_ats_sw_crc() {
        // TL = 5 but only two ATS bytes follow: a protocol error, not a panic.
        let ats = append_crc_a(&[0x05, 0x78]).unwrap();
        let mut t = MockTransceiver::new(false, vec![ats]);

        match Pcd::connect(&mut t, Fsdi::Fsd256, Cid::new(0).unwrap()) {
            Err(PcdError::Protocol(TypeAError::InvalidLength)) => {}
            other => panic!(
                "expected Protocol(InvalidLength), got {:?}",
                other.map(|_| ())
            ),
        }
    }

    #[test]
    fn connect_rejects_malformed_ats_hw_crc() {
        // Hardware CRC path: the transceiver hands over CRC-stripped bytes.
        let mut t = MockTransceiver::new(true, vec![frame_vec(&[0x05, 0x78])]);

        match Pcd::connect(&mut t, Fsdi::Fsd256, Cid::new(0).unwrap()) {
            Err(PcdError::Protocol(TypeAError::InvalidLength)) => {}
            other => panic!(
                "expected Protocol(InvalidLength), got {:?}",
                other.map(|_| ())
            ),
        }
    }

    #[test]
    fn connect_handles_one_byte_ats() {
        // The audit's crash input: an ATS declaring TL = 1. It is a legal
        // (if degenerate) ATS and must parse to the default format.
        let mut t = MockTransceiver::new(true, vec![frame_vec(&[0x01])]);
        let (_pcd, ats) = Pcd::connect(&mut t, Fsdi::Fsd256, Cid::new(0).unwrap()).unwrap();
        assert_eq!(ats.length, 1);
        assert_eq!(ats.format.fsci.fsc(), 32);
    }

    #[test]
    fn sw_crc_rejects_zero_crc_response() {
        // Software CRC mode: an I-Block ending in 00 00 is not exempt from
        // the CRC check just because the bytes are zero.
        let block = Block::new(Pcb::new(BlockType::IBlock).with_block_number(0))
            .with_payload(frame_vec(&[0xAA, 0xBB]));
        let mut raw = block.to_bytes_without_crc().unwrap();
        raw.try_push(0).unwrap();
        raw.try_push(0).unwrap();

        let mut t = MockTransceiver::new(false, vec![raw]);
        let ats = minimal_ats();
        let mut pcd = Pcd::new(&mut t, &ats, Fsdi::Fsd256, None, false);

        match pcd.exchange(&[0x01]) {
            Err(PcdError::Protocol(TypeAError::InvalidCrc(_))) => {}
            other => panic!("expected Protocol(InvalidCrc), got {:?}", other),
        }
    }

    #[test]
    fn sw_crc_accepts_correct_crc_response() {
        let resp = mock_iblock_response(0, &[0xAA, 0xBB], false);
        let mut t = MockTransceiver::new(false, vec![resp]);
        let ats = minimal_ats();
        let mut pcd = Pcd::new(&mut t, &ats, Fsdi::Fsd256, None, false);

        assert_eq!(pcd.exchange(&[0x01]).unwrap().as_slice(), &[0xAA, 0xBB]);
    }

    #[test]
    fn sw_crc_rejects_zero_crc_ats() {
        // The same goes for the ATS returned to RATS.
        let mut raw = frame_vec(&[0x05, 0x78, 0x80, 0x40, 0x02]);
        raw.try_push(0).unwrap();
        raw.try_push(0).unwrap();
        let mut t = MockTransceiver::new(false, vec![raw]);

        match Pcd::connect(&mut t, Fsdi::Fsd256, Cid::new(0).unwrap()) {
            Err(PcdError::Protocol(TypeAError::InvalidCrc(_))) => {}
            other => panic!("expected Protocol(InvalidCrc), got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn hw_crc_takes_crc_free_frames() {
        // Hardware CRC mode: the same CRC-free bytes are parsed through the
        // verified-input API, no synthesized epilogue involved.
        let mut t = MockTransceiver::new(true, vec![frame_vec(&[0x05, 0x78, 0x80, 0x40, 0x02])]);
        let (_pcd, ats) = Pcd::connect(&mut t, Fsdi::Fsd256, Cid::new(0).unwrap()).unwrap();
        assert_eq!(ats.length, 5);
    }

    // ── Limit tests ─────────────────────────────────────────────────────

    fn mock_rnak_response(block_number: u8) -> FrameVec {
        let pcb = Pcb::new(BlockType::RBlock)
            .with_block_number(block_number)
            .with_r_subtype(RBlockSubtype::Nak);
        Block::new(pcb).to_vec().unwrap()
    }

    fn assert_limit<E: core::fmt::Debug>(result: Result<ChainVec, PcdError<E>>, limit: Limit) {
        match result {
            Err(PcdError::Protocol(TypeAError::LimitExceeded(hit))) if hit == limit => {}
            other => panic!("expected {:?}, got {:?}", limit, other.map(|_| ())),
        }
    }

    #[test]
    fn send_chaining_nak_flood_terminates() {
        // A card that answers every chunk with a valid R(NAK) keeps the
        // reader retransmitting; the retransmission budget stops it.
        let mut t = MockTransceiver::new(false, vec![mock_rnak_response(0); 20]);
        let ats = small_fsc_ats(); // FSC 16 → 20 bytes of APDU chain
        let mut pcd = Pcd::new(&mut t, &ats, Fsdi::Fsd256, None, false);

        assert_limit(pcd.exchange(&[0x42u8; 20]), Limit::Retransmissions);
        // First transmission plus max_retransmissions retries, nothing more
        assert_eq!(t.sent.len(), 4);
    }

    #[test]
    fn response_chaining_is_bounded() {
        // A card that chains I-Blocks without ever ending the chain cannot
        // grow the assembled payload past max_chain_len.
        let mut t =
            MockTransceiver::new(false, vec![mock_iblock_response(0, &[0xAA; 4], true); 20]);
        let ats = minimal_ats();
        let mut pcd = Pcd::new(&mut t, &ats, Fsdi::Fsd256, None, false);
        pcd.set_limits(Limits {
            max_chain_len: 8,
            ..Limits::default()
        });

        assert_limit(pcd.exchange(&[0x01]), Limit::ChainLength);
        assert!(t.sent.len() <= 4);
    }

    #[test]
    fn response_frame_budget_is_bounded() {
        let mut t = MockTransceiver::new(false, vec![mock_iblock_response(0, &[0xAA], true); 20]);
        let ats = minimal_ats();
        let mut pcd = Pcd::new(&mut t, &ats, Fsdi::Fsd256, None, false);
        pcd.set_limits(Limits {
            max_frames: 3,
            ..Limits::default()
        });

        assert_limit(pcd.exchange(&[0x01]), Limit::Frames);
    }

    #[test]
    fn wtx_flood_terminates() {
        // S(WTX) is a valid, well-formed block; only the WTX budget ends
        // a card that asks for more time forever.
        let mut t = MockTransceiver::new(false, vec![mock_wtx_request(0x01); 20]);
        let ats = minimal_ats();
        let mut pcd = Pcd::new(&mut t, &ats, Fsdi::Fsd256, None, false);

        let tolerated = usize::from(pcd.limits().max_consecutive_wtx);
        assert_limit(pcd.exchange(&[0x01]), Limit::ConsecutiveWtx);
        // The initial I-Block plus one acknowledgement per tolerated S(WTX)
        assert_eq!(t.sent.len(), 1 + tolerated);
    }

    #[test]
    fn invalid_wtx_multiplier_terminates() {
        // WTXM 0 is RFU
        let mut t = MockTransceiver::new(false, vec![mock_wtx_request(0x00); 4]);
        let ats = minimal_ats();
        let mut pcd = Pcd::new(&mut t, &ats, Fsdi::Fsd256, None, false);

        assert_limit(pcd.exchange(&[0x01]), Limit::WtxValue);
        assert_eq!(t.sent.len(), 1);
    }

    #[test]
    fn oversized_response_is_rejected() {
        // The RATS announced FSD 16, so a 23-byte response frame is refused
        // before it is parsed or accumulated.
        let mut t = MockTransceiver::new(false, vec![mock_iblock_response(0, &[0xAA; 20], false)]);
        let ats = minimal_ats();
        let mut pcd = Pcd::new(&mut t, &ats, Fsdi::Fsd16, None, false);

        assert_limit(pcd.exchange(&[0x01]), Limit::FrameSize);
    }

    #[test]
    fn state_is_clean_after_a_limit_error() {
        // Nine S(WTX) trip the default consecutive budget, then a fresh
        // exchange runs normally: counters and chain start over.
        let mut responses = vec![mock_wtx_request(0x01); 9];
        responses.push(mock_iblock_response(1, &[0x90, 0x00], false));

        let mut t = MockTransceiver::new(false, responses);
        let ats = minimal_ats();
        let mut pcd = Pcd::new(&mut t, &ats, Fsdi::Fsd256, None, false);

        assert_limit(pcd.exchange(&[0x01]), Limit::ConsecutiveWtx);
        assert_eq!(pcd.exchange(&[0x02]).unwrap().as_slice(), &[0x90, 0x00]);
    }
}
