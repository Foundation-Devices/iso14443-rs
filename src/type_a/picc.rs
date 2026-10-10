// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! ISO14443 PICC (card emulation) transport layer.
//!
//! Handles the card side of the protocol: responds to activation
//! (REQA/anticollision/SELECT), RATS/ATS, and ISO14443-4 block exchange.

use super::{
    Ats, Block, Cid, Frame, PiccTransceiver, Sak, Tc, TypeAError,
    anticol_select::{SEL_CL1, SEL_CL2, SEL_CL3},
    atqa::AtqA,
    crc::{append_crc_a, split_crc_a},
    limits::{Limit, Limits},
    pcb::SBlockSubtype,
    pps::PpsParam,
    protocol::{Action, ProtocolHandler, Role},
    rats::RatsParam,
    vec::{ChainVec, FrameVec, VecExt},
};

/// Error during PICC protocol operations.
#[derive(Debug)]
pub enum PiccError<E> {
    /// The transceiver returned an error.
    PiccTransceiver(E),
    /// ISO14443 protocol violation.
    Protocol(TypeAError),
    /// The PCD sent S(DESELECT); session is over.
    Deselected,
}

impl<E> From<TypeAError> for PiccError<E> {
    fn from(e: TypeAError) -> Self {
        PiccError::Protocol(e)
    }
}

/// PICC activation state.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PiccState {
    /// Waiting for REQA/WUPA.
    Idle,
    /// Received REQA/WUPA, handling anticollision cascade.
    Ready { cascade_level: u8 },
    /// Fully selected (SAK sent with uid_complete), waiting for RATS.
    Active,
    /// RATS/ATS exchanged, in ISO14443-4 block protocol.
    Protocol,
    /// Halted by HLTA.
    Halted,
}

/// UID with compile-time size enforcement per ISO14443-3.
#[derive(Debug, Clone)]
pub enum Uid {
    /// Single-size UID (4 bytes, 1 cascade level).
    Single([u8; 4]),
    /// Double-size UID (7 bytes, 2 cascade levels).
    Double([u8; 7]),
    /// Triple-size UID (10 bytes, 3 cascade levels).
    Triple([u8; 10]),
}

impl Uid {
    fn uid_size(&self) -> super::atqa::UidSize {
        match self {
            Uid::Single(_) => super::atqa::UidSize::Single,
            Uid::Double(_) => super::atqa::UidSize::Double,
            Uid::Triple(_) => super::atqa::UidSize::Triple,
        }
    }

    fn as_slice(&self) -> &[u8] {
        match self {
            Uid::Single(u) => u,
            Uid::Double(u) => u,
            Uid::Triple(u) => u,
        }
    }

    fn cascade_levels(&self) -> u8 {
        match self {
            Uid::Single(_) => 1,
            Uid::Double(_) => 2,
            Uid::Triple(_) => 3,
        }
    }
}

/// Card identity and capabilities.
#[derive(Debug, Clone)]
pub struct PiccConfig {
    /// Card UID.
    pub uid: Uid,
    /// Bit-frame anticollision coding for ATQA.
    pub bit_frame_ac: super::atqa::BitFrameAntiCollision,
    /// ISO14443-4 configuration: ATS to send after RATS.
    /// Set via [`enable_14443_4`]. When `None`, the tag behaves as a
    /// non-ISO14443-4 card (e.g. NFC Forum Type 2).
    ats: Option<Ats>,
}

impl PiccConfig {
    /// Create a new PICC configuration.
    ///
    /// Defaults to 1 anticollision time slot. The ATQA is built
    /// automatically from the UID size.
    pub fn new(uid: Uid) -> Self {
        Self {
            uid,
            bit_frame_ac: super::atqa::BitFrameAntiCollision::Slot1,
            ats: None,
        }
    }

    /// Set the number of anticollision time slots advertised in ATQA.
    ///
    /// Defaults to `BitFrameAntiCollision::Slot1`.
    pub fn set_bit_frame_anticollision(&mut self, slot: super::atqa::BitFrameAntiCollision) {
        self.bit_frame_ac = slot;
    }

    /// Enable ISO14443-4 support with the given ATS.
    ///
    /// When enabled, the SAK will advertise ISO14443-4 compliance and
    /// the PICC will handle RATS/ATS negotiation.
    pub fn enable_14443_4(&mut self, ats: Ats) {
        self.ats = Some(ats);
    }

    /// Whether this card advertises ISO14443-4 compliance.
    pub fn is_14443_4(&self) -> bool {
        self.ats.is_some()
    }

    fn atqa(&self) -> AtqA {
        AtqA {
            uid_size: self.uid.uid_size(),
            bit_frame_ac: self.bit_frame_ac.clone(),
            proprietary_coding: 0,
        }
    }
}

/// ISO14443 PICC session.
///
/// Handles the card side of the protocol using a [`PiccTransceiver`] for
/// hardware I/O and [`ProtocolHandler`] for block-level state.
#[derive(Debug)]
pub struct Picc<'t, T: PiccTransceiver> {
    transceiver: &'t mut T,
    hw_crc: bool,
    config: PiccConfig,
    handler: ProtocolHandler,
    state: PiccState,
    /// PCD's max frame size (from RATS FSDI), used for chaining responses.
    fsd: usize,
}

impl<'t, T: PiccTransceiver> Picc<'t, T> {
    /// Create a new PICC session.
    pub fn new(t: &'t mut T, config: PiccConfig) -> Self {
        let hw_crc = t.try_enable_hw_crc().is_ok();
        Self {
            transceiver: t,
            hw_crc,
            config,
            handler: ProtocolHandler::new(Role::Picc, None),
            state: PiccState::Idle,
            fsd: 256, // default until RATS
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

    /// Wait for ISO14443-3A activation.
    ///
    /// Handles REQA → ATQA → anticollision cascade → SELECT → SAK.
    /// Returns when the UID is fully selected (state is `Active`).
    ///
    /// For ISO14443-4 tags, call [`Picc::wait_for_rats`] next.
    pub fn wait_for_activation(&mut self) -> Result<(), PiccError<T::Error>> {
        self.state = PiccState::Idle;
        loop {
            let raw = self
                .transceiver
                .receive()
                .map_err(PiccError::PiccTransceiver)?;

            match &self.state {
                PiccState::Idle => self.handle_idle(&raw)?,
                PiccState::Halted => {
                    // Only WUPA can wake from halted
                    if raw.as_slice() == [0x52] {
                        self.send_atqa()?;
                        self.state = PiccState::Ready { cascade_level: 0 };
                    }
                }
                PiccState::Ready { cascade_level } => {
                    let cl = *cascade_level;
                    self.handle_ready(&raw, cl)?;
                }
                PiccState::Active | PiccState::Protocol => unreachable!(),
            }

            if self.state == PiccState::Active {
                return Ok(());
            }
        }
    }

    /// Wait for RATS from the PCD and respond with ATS.
    ///
    /// Call after [`Picc::wait_for_activation`] for ISO14443-4 compliant
    /// tags. Transitions to `Protocol` state, ready for
    /// [`Picc::receive_command`]/[`Picc::send_response`].
    pub fn wait_for_rats(&mut self) -> Result<(), PiccError<T::Error>> {
        let raw = self
            .transceiver
            .receive()
            .map_err(PiccError::PiccTransceiver)?;
        self.handle_active(&raw)?;
        if self.state == PiccState::Protocol {
            Ok(())
        } else {
            Err(PiccError::Protocol(TypeAError::Other))
        }
    }

    /// Receive one complete APDU from the PCD.
    ///
    /// Handles PPS (if the PCD sends it), I-Block chaining (sends R(ACK)
    /// for each chained block), S(WTX) echo, and S(DESELECT).
    pub fn receive_command(&mut self) -> Result<ChainVec, PiccError<T::Error>> {
        self.handler.begin_exchange();
        loop {
            let raw = self
                .transceiver
                .receive()
                .map_err(PiccError::PiccTransceiver)?;

            // PPS: starts with 0xDx where x is CID
            if !raw.is_empty() && raw[0] & 0xF0 == 0xD0 {
                // Answered outside the block layer, so count it explicitly
                self.handler.note_frame()?;
                self.handle_pps(&raw)?;
                continue;
            }

            let block = self.parse_block(&raw)?;

            match self.handler.process_received(block)? {
                Action::Complete(data) => return Ok(data),
                Action::Reply(reply) => {
                    if reply.pcb.s_subtype == Some(SBlockSubtype::Deselect) {
                        self.send_block(&reply)?;
                        // Per ISO14443-3: after DESELECT the PICC enters
                        // HALT state (only responds to WUPA, not REQA).
                        self.state = PiccState::Halted;
                        return Err(PiccError::Deselected);
                    }
                    // R(ACK) for chaining or S(WTX) echo
                    self.send_block(&reply)?;
                }
                _ => return Err(PiccError::Protocol(TypeAError::Other)),
            }
        }
    }

    /// Send a response APDU back to the PCD.
    ///
    /// Handles chaining if the response exceeds the PCD's frame size (FSD).
    pub fn send_response(&mut self, data: &[u8]) -> Result<(), PiccError<T::Error>> {
        let cid_len = if self.handler.build_iblock(&[], false)?.cid.is_some() {
            1
        } else {
            0
        };
        let overhead = 1 + cid_len + 2; // PCB + optional CID + CRC
        let max_inf = self.fsd.saturating_sub(overhead);
        if max_inf == 0 {
            return Err(PiccError::Protocol(TypeAError::Other));
        }

        let mut offset = 0;
        while offset < data.len() {
            let end = core::cmp::min(offset + max_inf, data.len());
            let chaining = end < data.len();
            // Rule D toggled the block number when the command came in, so
            // the I-Block is built with the number it should carry and the
            // PICC does not toggle again on the way out.
            let iblock = self.handler.build_iblock(&data[offset..end], chaining)?;
            self.send_block(&iblock)?;

            if !chaining {
                break;
            }

            // Wait for the R(ACK) that releases the next chunk. Rule 11 can
            // ask for this one again, and Rule 12 for an R(ACK) in between;
            // the work limits bound how long that can go on.
            loop {
                let raw = self
                    .transceiver
                    .receive()
                    .map_err(PiccError::PiccTransceiver)?;
                let block = self.parse_block(&raw)?;
                match self.handler.process_received(block)? {
                    Action::ChainingAck => {
                        offset = end;
                        break;
                    }
                    Action::ChainingRetransmit => {
                        self.send_block(&iblock)?;
                    }
                    Action::Reply(reply) => {
                        // §7.5.5: an S(DESELECT) is accepted at any time,
                        // chaining included.
                        let deselect = reply.pcb.s_subtype == Some(SBlockSubtype::Deselect);
                        self.send_block(&reply)?;
                        if deselect {
                            self.state = PiccState::Halted;
                            return Err(PiccError::Deselected);
                        }
                    }
                    _ => return Err(PiccError::Protocol(TypeAError::Other)),
                }
            }
        }
        Ok(())
    }

    // ── Activation handlers ─────────────────────────────────────────────

    fn handle_idle(&mut self, raw: &[u8]) -> Result<(), PiccError<T::Error>> {
        match raw {
            [0x26] | [0x52] => {
                // REQA or WUPA
                self.send_atqa()?;
                self.state = PiccState::Ready { cascade_level: 0 };
            }
            _ => {} // Ignore unknown commands in idle
        }
        Ok(())
    }

    fn handle_ready(&mut self, raw: &[u8], cascade_level: u8) -> Result<(), PiccError<T::Error>> {
        if raw.len() < 2 {
            return Ok(()); // Ignore short frames
        }

        let sel = raw[0];
        let expected_sel = match cascade_level {
            0 => SEL_CL1,
            1 => SEL_CL2,
            2 => SEL_CL3,
            _ => return Err(PiccError::Protocol(TypeAError::Other)),
        };

        if sel != expected_sel {
            return Ok(()); // Wrong cascade level, ignore
        }

        if raw.len() == 2 {
            // Anticollision: SEL + NVB(0x20) → respond with UID+BCC
            let uid_bcc = self.uid_bcc_for_level(cascade_level)?;
            let mut resp = FrameVec::new();
            resp.try_extend(&uid_bcc)?;
            self.transceiver
                .send(&Frame::BitOriented(resp))
                .map_err(PiccError::PiccTransceiver)?;
        } else if raw[1] == 0x70 {
            // SELECT: SEL + NVB(0x70) + UID[4] + BCC (+ CRC on the wire)
            if self.strip_crc(raw)?.len() != 7 {
                return Ok(()); // Malformed SELECT, ignore
            }

            // Respond with SAK
            let is_last_level = self.is_last_cascade_level(cascade_level);
            let sak = Sak {
                uid_complete: is_last_level,
                iso14443_4_compliant: self.config.is_14443_4(),
            };
            self.send_sak(&sak)?;

            if is_last_level {
                self.state = PiccState::Active;
            } else {
                self.state = PiccState::Ready {
                    cascade_level: cascade_level + 1,
                };
            }
        }
        Ok(())
    }

    fn handle_active(&mut self, raw: &[u8]) -> Result<(), PiccError<T::Error>> {
        if raw.is_empty() {
            return Ok(());
        }

        match raw[0] {
            0xe0 => {
                // RATS: E0 + param (+ CRC on the wire)
                let param_byte = match *self.strip_crc(raw)? {
                    [0xe0, param] => param,
                    _ => return Err(PiccError::Protocol(TypeAError::InvalidLength)),
                };
                let rats = RatsParam::try_from(param_byte)?;
                self.fsd = rats.fsdi().fsd();
                // A card without CID support ignores the CID proposed in RATS
                // and never sends one (§5.6.3).
                let cid = self
                    .config
                    .ats
                    .as_ref()
                    .filter(|ats| ats.tc.contains(Tc::CID_SUPP))
                    .and_then(|_| Cid::new(rats.cid().value()));
                self.handler =
                    ProtocolHandler::with_limits(Role::Picc, cid, *self.handler.limits());

                // Send ATS
                self.send_ats()?;
                self.state = PiccState::Protocol;
            }
            // HLTA: 50 00 (+ CRC on the wire)
            0x50 if self.strip_crc(raw)? == [0x50, 0x00] => {
                self.state = PiccState::Halted;
            }
            _ => {} // Ignore unknown in Active state
        }
        Ok(())
    }

    /// Handle PPS request: validate, respond with PPSS byte.
    fn handle_pps(&mut self, raw: &[u8]) -> Result<(), PiccError<T::Error>> {
        // Parse and validate PPS (the software-CRC path checks the CRC)
        let pps = PpsParam::from_crc_verified(self.strip_crc(raw)?)?;

        // Respond with PPSS byte (0xD0 + CID)
        let ppss = 0xd0 + u8::from(&pps.cid);
        if self.hw_crc {
            let mut data = FrameVec::new();
            data.try_push(ppss)?;
            self.transceiver
                .send(&Frame::Standard(data))
                .map_err(PiccError::PiccTransceiver)?;
        } else {
            let data = append_crc_a(&[ppss])?;
            self.transceiver
                .send(&Frame::Standard(data))
                .map_err(PiccError::PiccTransceiver)?;
        }
        Ok(())
    }

    // ── Send helpers ────────────────────────────────────────────────────

    fn send_atqa(&mut self) -> Result<(), PiccError<T::Error>> {
        let bytes = self.config.atqa().to_bytes();
        let mut data = FrameVec::new();
        data.try_extend(&bytes)?;
        self.transceiver
            .send(&Frame::Short(data))
            .map_err(PiccError::PiccTransceiver)
    }

    fn send_sak(&mut self, sak: &Sak) -> Result<(), PiccError<T::Error>> {
        let byte = sak.to_byte();
        if self.hw_crc {
            let mut data = FrameVec::new();
            data.try_push(byte)?;
            self.transceiver
                .send(&Frame::Standard(data))
                .map_err(PiccError::PiccTransceiver)
        } else {
            let data = append_crc_a(&[byte])?;
            self.transceiver
                .send(&Frame::Standard(data))
                .map_err(PiccError::PiccTransceiver)
        }
    }

    fn send_ats(&mut self) -> Result<(), PiccError<T::Error>> {
        let ats = self
            .config
            .ats
            .as_ref()
            .ok_or(PiccError::Protocol(TypeAError::Other))?;
        let ats_bytes = ats.to_bytes()?;
        if self.hw_crc {
            self.transceiver
                .send(&Frame::Standard(ats_bytes))
                .map_err(PiccError::PiccTransceiver)
        } else {
            let data = append_crc_a(ats_bytes.as_slice())?;
            self.transceiver
                .send(&Frame::Standard(data))
                .map_err(PiccError::PiccTransceiver)
        }
    }

    fn send_block(&mut self, block: &Block) -> Result<(), PiccError<T::Error>> {
        let data = block.to_bytes_without_crc()?;
        let frame = if self.hw_crc {
            Frame::Standard(data)
        } else {
            Frame::Standard(append_crc_a(&data)?)
        };
        self.transceiver
            .send(&frame)
            .map_err(PiccError::PiccTransceiver)
    }

    /// Parse a received command frame into a Block.
    ///
    /// The ATS told the PCD how large a frame this card accepts (FSC);
    /// anything longer is refused before it is parsed or accumulated.
    fn parse_block(&self, raw: &[u8]) -> Result<Block, PiccError<T::Error>> {
        let on_air_len = if self.hw_crc {
            raw.len() + 2
        } else {
            raw.len()
        };
        if on_air_len > self.fsc() {
            return Err(PiccError::Protocol(Limit::FrameSize.into()));
        }
        Ok(Block::from_crc_verified(self.strip_crc(raw)?)?)
    }

    /// Maximum frame size this card accepts, as advertised in its ATS.
    fn fsc(&self) -> usize {
        self.config
            .ats
            .as_ref()
            .map_or(256, |ats| ats.format.fsci.fsc())
    }

    /// Return the command data of a received standard frame.
    ///
    /// With hardware CRC the transceiver has already validated and stripped
    /// the CRC_A; otherwise it is still attached and must match the data.
    fn strip_crc<'r>(&self, raw: &'r [u8]) -> Result<&'r [u8], PiccError<T::Error>> {
        if self.hw_crc {
            Ok(raw)
        } else {
            Ok(split_crc_a(raw)?)
        }
    }

    // ── UID cascade helpers ─────────────────────────────────────────────

    fn is_last_cascade_level(&self, level: u8) -> bool {
        level + 1 >= self.config.uid.cascade_levels()
    }

    /// Build the 5-byte UID+BCC response for a given cascade level.
    fn uid_bcc_for_level(&self, level: u8) -> Result<[u8; 5], TypeAError> {
        let uid = self.config.uid.as_slice();
        let levels = self.config.uid.cascade_levels();

        let mut bytes = [0u8; 4];
        match (levels, level) {
            (1, 0) => bytes.copy_from_slice(&uid[0..4]),
            (2, 0) => {
                bytes[0] = 0x88; // cascade tag
                bytes[1..4].copy_from_slice(&uid[0..3]);
            }
            (2, 1) => bytes.copy_from_slice(&uid[3..7]),
            (3, 0) => {
                bytes[0] = 0x88;
                bytes[1..4].copy_from_slice(&uid[0..3]);
            }
            (3, 1) => {
                bytes[0] = 0x88;
                bytes[1..4].copy_from_slice(&uid[3..6]);
            }
            (3, 2) => bytes.copy_from_slice(&uid[6..10]),
            _ => return Err(TypeAError::Other),
        }

        let bcc = bytes[0] ^ bytes[1] ^ bytes[2] ^ bytes[3];
        Ok([bytes[0], bytes[1], bytes[2], bytes[3], bcc])
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    use super::super::crc::append_crc_a;
    use super::super::pcb::{BlockType, Pcb, RBlockSubtype};
    use super::super::vec::VecExt;
    use super::*;

    #[derive(Debug)]
    struct MockError;

    /// Mock PiccTransceiver that replays scripted receives and records sends.
    struct MockPiccTransceiver {
        receives: Vec<FrameVec>,
        sends: Vec<FrameVec>,
        recv_idx: usize,
    }

    impl MockPiccTransceiver {
        fn new(receives: Vec<FrameVec>) -> Self {
            Self {
                receives,
                sends: Vec::new(),
                recv_idx: 0,
            }
        }
    }

    impl PiccTransceiver for MockPiccTransceiver {
        type Error = MockError;

        fn receive(&mut self) -> Result<FrameVec, MockError> {
            if self.recv_idx < self.receives.len() {
                let data = self.receives[self.recv_idx].clone();
                self.recv_idx += 1;
                Ok(data)
            } else {
                Err(MockError)
            }
        }

        fn send(&mut self, frame: &Frame) -> Result<(), MockError> {
            let mut copy = FrameVec::new();
            let _ = copy.try_extend(frame.data());
            self.sends.push(copy);
            Ok(())
        }

        fn try_enable_hw_crc(&mut self) -> Result<(), MockError> {
            Err(MockError) // no HW CRC in tests
        }
    }

    fn frame_vec(data: &[u8]) -> FrameVec {
        let mut v = FrameVec::new();
        v.try_extend(data).unwrap();
        v
    }

    fn test_config_4byte() -> PiccConfig {
        use super::super::atqa::BitFrameAntiCollision;
        use super::super::ats::{Fsci, Ta, Tb, Tc};
        let mut config = PiccConfig::new(Uid::Single([0x01, 0x02, 0x03, 0x04]));
        config.set_bit_frame_anticollision(BitFrameAntiCollision::Slot4);
        config.enable_14443_4(Ats::new(
            Fsci::Fsc256,
            Ta::SAME_D_SUPP,
            Tb::default(),
            Tc::CID_SUPP,
        ));
        config
    }

    /// Build a SELECT command with CRC for a given SEL and UID+BCC.
    fn select_cmd(sel: u8, uid_bcc: &[u8; 5]) -> FrameVec {
        let mut data = vec![sel, 0x70];
        data.extend_from_slice(uid_bcc);
        let raw: Vec<u8> = data;
        append_crc_a(&raw).unwrap()
    }

    /// Build a RATS command with CRC.
    fn rats_cmd(fsdi: u8, cid: u8) -> FrameVec {
        let param = (fsdi << 4) | (cid & 0x0f);
        append_crc_a(&[0xe0, param]).unwrap()
    }

    #[test]
    fn activation_4byte_uid() {
        let uid_bcc = [0x01, 0x02, 0x03, 0x04, 0x01 ^ 0x02 ^ 0x03 ^ 0x04];
        let receives = vec![
            frame_vec(&[0x26]),         // REQA
            frame_vec(&[0x93, 0x20]),   // anticollision CL1
            select_cmd(0x93, &uid_bcc), // SELECT CL1
            rats_cmd(8, 0),             // RATS (FSDI=8 → FSD=256, CID=0)
        ];

        let mut t = MockPiccTransceiver::new(receives);
        let config = test_config_4byte();
        let mut picc = Picc::new(&mut t, config);

        picc.wait_for_activation().unwrap();
        picc.wait_for_rats().unwrap();

        // Check sends: ATQA, UID+BCC, SAK+CRC, ATS+CRC
        assert_eq!(t.sends.len(), 4);
        // ATQA (UidSize::Single=0, BitFrameAntiCollision::Slot1=4)
        // ATQA: UidSize::Single (0 << 6) | BitFrameAntiCollision::Slot4 (4)
        assert_eq!(t.sends[0].as_slice(), &[0x04, 0x00]);
        // UID+BCC
        assert_eq!(t.sends[1].as_slice(), &uid_bcc);
        // SAK (0x20 = ISO14443-4, uid_complete) + CRC
        assert_eq!(t.sends[2].len(), 3); // SAK + 2 CRC bytes
        assert_eq!(t.sends[2][0], 0x20);
    }

    #[test]
    fn receive_single_iblock() {
        // Set up an activated PICC, then receive a single I-Block
        let uid_bcc = [0x01, 0x02, 0x03, 0x04, 0x01 ^ 0x02 ^ 0x03 ^ 0x04];

        // Build an I-Block command from PCD
        let pcb = Pcb::new(BlockType::IBlock).with_block_number(0);
        let iblock = Block::new(pcb).with_payload(frame_vec(&[0xAA, 0xBB]));
        let iblock_bytes = append_crc_a(&iblock.to_bytes_without_crc().unwrap()).unwrap();

        let receives = vec![
            frame_vec(&[0x26]),
            frame_vec(&[0x93, 0x20]),
            select_cmd(0x93, &uid_bcc),
            rats_cmd(8, 0),
            iblock_bytes,
        ];

        let mut t = MockPiccTransceiver::new(receives);
        let mut picc = Picc::new(&mut t, test_config_4byte());
        picc.wait_for_activation().unwrap();
        picc.wait_for_rats().unwrap();

        let apdu = picc.receive_command().unwrap();
        assert_eq!(apdu.as_slice(), &[0xAA, 0xBB]);
    }

    #[test]
    fn send_single_response() {
        let uid_bcc = [0x01, 0x02, 0x03, 0x04, 0x01 ^ 0x02 ^ 0x03 ^ 0x04];

        let pcb = Pcb::new(BlockType::IBlock).with_block_number(0);
        let iblock = Block::new(pcb).with_payload(frame_vec(&[0x01]));
        let iblock_bytes = append_crc_a(&iblock.to_bytes_without_crc().unwrap()).unwrap();

        let receives = vec![
            frame_vec(&[0x26]),
            frame_vec(&[0x93, 0x20]),
            select_cmd(0x93, &uid_bcc),
            rats_cmd(8, 0),
            iblock_bytes,
        ];

        let mut t = MockPiccTransceiver::new(receives);
        let mut picc = Picc::new(&mut t, test_config_4byte());
        picc.wait_for_activation().unwrap();
        picc.wait_for_rats().unwrap();

        let _ = picc.receive_command().unwrap();
        picc.send_response(&[0x90, 0x00]).unwrap();

        // Last send should be an I-Block with payload [0x90, 0x00]
        let last = t.sends.last().unwrap();
        // Parse it: strip CRC, parse block
        let block = Block::try_from(last.as_slice()).unwrap();
        assert_eq!(block.block_type(), BlockType::IBlock);
        assert_eq!(block.payload.as_slice(), &[0x90, 0x00]);
    }

    #[test]
    fn no_cid_support_means_no_cid_in_responses() {
        use super::super::ats::{Fsci, Ta, Tb, Tc};
        let mut config = test_config_4byte();
        config.enable_14443_4(Ats::new(
            Fsci::Fsc256,
            Ta::SAME_D_SUPP,
            Tb::default(),
            Tc::empty(),
        ));

        let uid_bcc = [0x01, 0x02, 0x03, 0x04, 0x04];
        let pcb = Pcb::new(BlockType::IBlock).with_block_number(0);
        let iblock = Block::new(pcb).with_payload(frame_vec(&[0x01]));
        let receives = vec![
            frame_vec(&[0x26]),
            frame_vec(&[0x93, 0x20]),
            select_cmd(0x93, &uid_bcc),
            rats_cmd(8, 5), // the PCD proposes CID 5
            append_crc_a(&iblock.to_bytes_without_crc().unwrap()).unwrap(),
        ];

        let mut t = MockPiccTransceiver::new(receives);
        let mut picc = Picc::new(&mut t, config);
        picc.wait_for_activation().unwrap();
        picc.wait_for_rats().unwrap();
        let _ = picc.receive_command().unwrap();
        picc.send_response(&[0x90, 0x00]).unwrap();

        let block = Block::try_from(t.sends.last().unwrap().as_slice()).unwrap();
        assert!(block.cid.is_none());
    }

    #[test]
    fn deselect_handling() {
        let uid_bcc = [0x01, 0x02, 0x03, 0x04, 0x01 ^ 0x02 ^ 0x03 ^ 0x04];

        // Build S(DESELECT) from PCD
        let pcb = Pcb::new(BlockType::SBlock).with_s_subtype(SBlockSubtype::Deselect);
        let deselect = Block::new(pcb);
        let deselect_bytes = append_crc_a(&deselect.to_bytes_without_crc().unwrap()).unwrap();

        let receives = vec![
            frame_vec(&[0x26]),
            frame_vec(&[0x93, 0x20]),
            select_cmd(0x93, &uid_bcc),
            rats_cmd(8, 0),
            deselect_bytes,
        ];

        let mut t = MockPiccTransceiver::new(receives);
        let mut picc = Picc::new(&mut t, test_config_4byte());
        picc.wait_for_activation().unwrap();
        picc.wait_for_rats().unwrap();

        match picc.receive_command() {
            Err(PiccError::Deselected) => {} // expected
            other => panic!("expected Deselected, got {:?}", other),
        }
    }

    #[test]
    fn uid_bcc_4byte() {
        let config = test_config_4byte();
        let mut t = MockPiccTransceiver::new(vec![]);
        let picc = Picc::new(&mut t, config);

        let bcc = picc.uid_bcc_for_level(0).unwrap();
        assert_eq!(bcc, [0x01, 0x02, 0x03, 0x04, 0x01 ^ 0x02 ^ 0x03 ^ 0x04]);
    }

    #[test]
    fn uid_bcc_7byte() {
        let mut config = test_config_4byte();
        config.uid = Uid::Double([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        let mut t = MockPiccTransceiver::new(vec![]);
        let picc = Picc::new(&mut t, config);

        // Level 0: cascade tag + first 3 UID bytes
        let bcc0 = picc.uid_bcc_for_level(0).unwrap();
        assert_eq!(bcc0[0], 0x88); // cascade tag
        assert_eq!(&bcc0[1..4], &[0x01, 0x02, 0x03]);
        assert_eq!(bcc0[4], 0x88 ^ 0x01 ^ 0x02 ^ 0x03);

        // Level 1: remaining 4 UID bytes
        let bcc1 = picc.uid_bcc_for_level(1).unwrap();
        assert_eq!(&bcc1[0..4], &[0x04, 0x05, 0x06, 0x07]);
        assert_eq!(bcc1[4], 0x04 ^ 0x05 ^ 0x06 ^ 0x07);
    }

    /// A frame carrying the all-zero CRC sentinel instead of its CRC_A.
    fn zero_crc(data: &[u8]) -> FrameVec {
        let mut v = frame_vec(data);
        v.try_push(0).unwrap();
        v.try_push(0).unwrap();
        v
    }

    #[test]
    fn select_with_zero_crc_is_rejected() {
        let uid_bcc = [0x01, 0x02, 0x03, 0x04, 0x04];
        let mut select = vec![0x93, 0x70];
        select.extend_from_slice(&uid_bcc);

        let receives = vec![
            frame_vec(&[0x26]),
            frame_vec(&[0x93, 0x20]),
            zero_crc(&select),
        ];

        let mut t = MockPiccTransceiver::new(receives);
        let mut picc = Picc::new(&mut t, test_config_4byte());

        match picc.wait_for_activation() {
            Err(PiccError::Protocol(TypeAError::InvalidCrc(_))) => {}
            other => panic!("expected Protocol(InvalidCrc), got {:?}", other),
        }
    }

    #[test]
    fn rats_with_zero_crc_is_rejected() {
        let uid_bcc = [0x01, 0x02, 0x03, 0x04, 0x04];
        let receives = vec![
            frame_vec(&[0x26]),
            frame_vec(&[0x93, 0x20]),
            select_cmd(0x93, &uid_bcc),
            zero_crc(&[0xe0, 0x80]),
        ];

        let mut t = MockPiccTransceiver::new(receives);
        let mut picc = Picc::new(&mut t, test_config_4byte());
        picc.wait_for_activation().unwrap();

        match picc.wait_for_rats() {
            Err(PiccError::Protocol(TypeAError::InvalidCrc(_))) => {}
            other => panic!("expected Protocol(InvalidCrc), got {:?}", other),
        }
    }

    #[test]
    fn iblock_with_zero_crc_is_rejected() {
        let uid_bcc = [0x01, 0x02, 0x03, 0x04, 0x04];
        let receives = vec![
            frame_vec(&[0x26]),
            frame_vec(&[0x93, 0x20]),
            select_cmd(0x93, &uid_bcc),
            rats_cmd(8, 0),
            zero_crc(&[0x02, 0xAA, 0xBB]),
        ];

        let mut t = MockPiccTransceiver::new(receives);
        let mut picc = Picc::new(&mut t, test_config_4byte());
        picc.wait_for_activation().unwrap();
        picc.wait_for_rats().unwrap();

        match picc.receive_command() {
            Err(PiccError::Protocol(TypeAError::InvalidCrc(_))) => {}
            other => panic!("expected Protocol(InvalidCrc), got {:?}", other),
        }
    }

    // ── A reader that follows the numbering rules ────────────────────────

    /// A PCD that applies §7.5.3 and §7.5.4 literally, driving the card
    /// through whole exchanges instead of replaying a fixed script.
    ///
    /// Rule A: block number initialised to 0. Rule B: toggle when an
    /// I-Block or an R(ACK) carrying the current number arrives. Rule 7:
    /// that R(ACK) releases the next chunk. Rule 6: any other number asks
    /// for the last chunk again.
    struct SpecReader {
        /// Activation frames, handed over before the block protocol starts.
        prelude: Vec<FrameVec>,
        prelude_idx: usize,
        block_number: u8,
        /// One entry per exchange: the command, split into chained chunks.
        commands: Vec<Vec<Vec<u8>>>,
        command: usize,
        chunk: usize,
        /// The frame the card is handed next.
        pending: Option<FrameVec>,
        /// Response APDUs as the reader assembled them.
        assembled: Vec<Vec<u8>>,
        partial: Vec<u8>,
        /// How often Rule 6 fired, or a repeated I-Block turned up. A card
        /// in step causes neither.
        repeats: usize,
    }

    impl SpecReader {
        fn new(prelude: Vec<FrameVec>, commands: Vec<Vec<Vec<u8>>>) -> Self {
            Self {
                prelude,
                prelude_idx: 0,
                block_number: 0, // Rule A
                commands,
                command: 0,
                chunk: 0,
                pending: None,
                assembled: Vec::new(),
                partial: Vec::new(),
                repeats: 0,
            }
        }

        fn queue(&mut self, block: Block) {
            self.pending = Some(block.to_vec().unwrap());
        }

        /// Send the chunk the reader is on, chained unless it is the last.
        fn queue_chunk(&mut self) {
            let chunks = &self.commands[self.command];
            let payload = chunks[self.chunk].clone();
            let chaining = self.chunk + 1 < chunks.len();
            let pcb = Pcb::new(BlockType::IBlock)
                .with_block_number(self.block_number)
                .with_chaining(chaining);
            self.queue(Block::new(pcb).with_payload(frame_vec(&payload)));
        }

        fn queue_rack(&mut self) {
            let pcb = Pcb::new(BlockType::RBlock)
                .with_block_number(self.block_number)
                .with_r_subtype(RBlockSubtype::Ack);
            self.queue(Block::new(pcb));
        }

        /// React to a block from the card.
        fn handle(&mut self, block: Block) {
            match block.block_type() {
                BlockType::RBlock => {
                    if block.block_number() == self.block_number {
                        // Rules B and 7: chunk taken, carry on
                        self.block_number = 1 - self.block_number;
                        self.chunk += 1;
                    } else {
                        // Rule 6: send the same chunk again
                        self.repeats += 1;
                    }
                    self.queue_chunk();
                }
                BlockType::IBlock => {
                    if block.block_number() != self.block_number {
                        // Rule B did not fire: a block already taken in
                        self.repeats += 1;
                        self.queue_rack();
                        return;
                    }
                    self.block_number = 1 - self.block_number;
                    self.partial.extend_from_slice(block.payload.as_slice());
                    if block.is_chaining() {
                        // Rule 2
                        self.queue_rack();
                    } else {
                        let apdu = core::mem::take(&mut self.partial);
                        self.assembled.push(apdu);
                        self.command += 1;
                        self.chunk = 0;
                        if self.command < self.commands.len() {
                            self.queue_chunk();
                        }
                    }
                }
                BlockType::SBlock => {}
            }
        }
    }

    impl PiccTransceiver for SpecReader {
        type Error = MockError;

        fn receive(&mut self) -> Result<FrameVec, MockError> {
            if self.prelude_idx < self.prelude.len() {
                let frame = self.prelude[self.prelude_idx].clone();
                self.prelude_idx += 1;
                return Ok(frame);
            }
            self.pending.take().ok_or(MockError)
        }

        fn send(&mut self, frame: &Frame) -> Result<(), MockError> {
            if self.prelude_idx < self.prelude.len() {
                return Ok(()); // ATQA, UID, SAK — still activating
            }
            match Block::try_from(frame.data()) {
                // The ATS, sent once the last prelude frame (RATS) is in:
                // the block protocol starts with the reader's first command
                Err(_) => self.queue_chunk(),
                Ok(block) => self.handle(block),
            }
            Ok(())
        }

        fn try_enable_hw_crc(&mut self) -> Result<(), MockError> {
            Err(MockError)
        }
    }

    /// Activation frames a reader sends before the block protocol.
    fn prelude() -> Vec<FrameVec> {
        let uid_bcc = [0x01, 0x02, 0x03, 0x04, 0x04]; // 0x04 is the BCC
        vec![
            frame_vec(&[0x26]),
            frame_vec(&[0x93, 0x20]),
            select_cmd(0x93, &uid_bcc),
            rats_cmd(5, 0), // FSDI 5 → FSD 64
        ]
    }

    /// Run `commands` against a card that echoes each APDU back with a
    /// status word, and return the reader for inspection.
    fn run_exchanges(commands: Vec<Vec<Vec<u8>>>) -> SpecReader {
        let count = commands.len();
        let mut reader = SpecReader::new(prelude(), commands);
        {
            let mut picc = Picc::new(&mut reader, test_config_4byte());
            picc.wait_for_activation().unwrap();
            picc.wait_for_rats().unwrap();

            for i in 0..count {
                let apdu = picc.receive_command().unwrap_or_else(|e| {
                    panic!("exchange {i}: receive_command failed: {e:?}");
                });
                let mut response: Vec<u8> = apdu.as_slice().to_vec();
                response.extend_from_slice(&[0x90, 0x00]);
                picc.send_response(&response)
                    .unwrap_or_else(|e| panic!("exchange {i}: send_response failed: {e:?}"));
            }
        }
        reader
    }

    #[test]
    fn spec_reader_single_block_exchanges() {
        let reader = run_exchanges(vec![
            vec![vec![0x00, 0xA4]],
            vec![vec![0x00, 0xB0]],
            vec![vec![0x00, 0xB1]],
        ]);

        assert_eq!(
            reader.assembled,
            vec![
                vec![0x00, 0xA4, 0x90, 0x00],
                vec![0x00, 0xB0, 0x90, 0x00],
                vec![0x00, 0xB1, 0x90, 0x00],
            ]
        );
        assert_eq!(reader.repeats, 0, "the reader had to repeat a block");
    }

    #[test]
    fn spec_reader_chained_command_and_response() {
        // The card's ATS announces FSC 256 but the RATS announced FSD 64,
        // so a 100-byte echo comes back chained. The command is chained
        // too, which exercises Rules D, E and 13 in one exchange.
        let command: Vec<u8> = (0..100u8).collect();
        let chunks: Vec<Vec<u8>> = command.chunks(30).map(<[u8]>::to_vec).collect();
        let reader = run_exchanges(vec![chunks.clone(), chunks]);

        let mut expected = command.clone();
        expected.extend_from_slice(&[0x90, 0x00]);
        assert_eq!(reader.assembled, vec![expected.clone(), expected]);
        assert_eq!(reader.repeats, 0, "the reader had to repeat a block");
    }

    // ── Limit tests ─────────────────────────────────────────────────────

    /// Activation frames followed by `commands`, ready for receive_command().
    fn activated(commands: Vec<FrameVec>) -> Vec<FrameVec> {
        let uid_bcc = [0x01, 0x02, 0x03, 0x04, 0x04];
        let mut receives = vec![
            frame_vec(&[0x26]),
            frame_vec(&[0x93, 0x20]),
            select_cmd(0x93, &uid_bcc),
            rats_cmd(8, 0),
        ];
        receives.extend(commands);
        receives
    }

    /// A chained I-Block command with the given payload.
    fn chained_iblock(block_number: u8, payload: &[u8]) -> FrameVec {
        let pcb = Pcb::new(BlockType::IBlock)
            .with_block_number(block_number)
            .with_chaining(true);
        Block::new(pcb)
            .with_payload(frame_vec(payload))
            .to_vec()
            .unwrap()
    }

    /// `count` chained I-Block commands with the same payload, numbered the
    /// way a reader in step with the card numbers them: 0, 1, 0, 1, …
    fn chained_command(count: usize, payload: &[u8]) -> Vec<FrameVec> {
        (0..count)
            .map(|i| chained_iblock((i % 2) as u8, payload))
            .collect()
    }

    fn assert_limit<E: core::fmt::Debug>(result: Result<ChainVec, PiccError<E>>, limit: Limit) {
        match result {
            Err(PiccError::Protocol(TypeAError::LimitExceeded(hit))) if hit == limit => {}
            other => panic!("expected {:?}, got {:?}", limit, other.map(|_| ())),
        }
    }

    #[test]
    fn command_chaining_is_bounded() {
        // A reader that chains command I-Blocks without end cannot grow the
        // card's assembled APDU past max_chain_len.
        let receives = activated(chained_command(20, &[0xAA; 4]));

        let mut t = MockPiccTransceiver::new(receives);
        let mut picc = Picc::new(&mut t, test_config_4byte());
        picc.set_limits(Limits {
            max_chain_len: 8,
            ..Limits::default()
        });
        picc.wait_for_activation().unwrap();
        picc.wait_for_rats().unwrap();

        assert_limit(picc.receive_command(), Limit::ChainLength);
    }

    #[test]
    fn command_frame_budget_is_bounded() {
        let receives = activated(chained_command(20, &[0xAA]));

        let mut t = MockPiccTransceiver::new(receives);
        let mut picc = Picc::new(&mut t, test_config_4byte());
        picc.set_limits(Limits {
            max_frames: 3,
            ..Limits::default()
        });
        picc.wait_for_activation().unwrap();
        picc.wait_for_rats().unwrap();

        assert_limit(picc.receive_command(), Limit::Frames);
    }

    #[test]
    fn repeated_pps_is_bounded() {
        // PPS is answered outside the block layer, so it needs the frame
        // budget of its own to not become a free loop.
        let pps = append_crc_a(&[0xd0, 0x11, 0x00]).unwrap();
        let receives = activated(vec![pps; 20]);

        let mut t = MockPiccTransceiver::new(receives);
        let mut picc = Picc::new(&mut t, test_config_4byte());
        picc.set_limits(Limits {
            max_frames: 4,
            ..Limits::default()
        });
        picc.wait_for_activation().unwrap();
        picc.wait_for_rats().unwrap();

        assert_limit(picc.receive_command(), Limit::Frames);
    }

    #[test]
    fn oversized_command_is_rejected() {
        // The card's ATS announces FSC 16, so a longer command frame is
        // refused before it is parsed or accumulated.
        let mut config = test_config_4byte();
        {
            use super::super::ats::{Fsci, Ta, Tb, Tc};
            config.enable_14443_4(Ats::new(
                Fsci::Fsc16,
                Ta::SAME_D_SUPP,
                Tb::default(),
                Tc::CID_SUPP,
            ));
        }
        let receives = activated(vec![chained_iblock(0, &[0xAA; 20])]);

        let mut t = MockPiccTransceiver::new(receives);
        let mut picc = Picc::new(&mut t, config);
        picc.wait_for_activation().unwrap();
        picc.wait_for_rats().unwrap();

        assert_limit(picc.receive_command(), Limit::FrameSize);
    }

    #[test]
    fn state_is_clean_after_a_limit_error() {
        let good = {
            let pcb = Pcb::new(BlockType::IBlock).with_block_number(0);
            Block::new(pcb)
                .with_payload(frame_vec(&[0x90, 0x00]))
                .to_vec()
                .unwrap()
        };
        let mut commands = chained_command(3, &[0xAA; 4]);
        commands.push(good);
        let receives = activated(commands);

        let mut t = MockPiccTransceiver::new(receives);
        let mut picc = Picc::new(&mut t, test_config_4byte());
        picc.set_limits(Limits {
            max_chain_len: 8,
            ..Limits::default()
        });
        picc.wait_for_activation().unwrap();
        picc.wait_for_rats().unwrap();

        assert_limit(picc.receive_command(), Limit::ChainLength);
        // The dropped chain is not prepended to the next command
        assert_eq!(picc.receive_command().unwrap().as_slice(), &[0x90, 0x00]);
    }
}
