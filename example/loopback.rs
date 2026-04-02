// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Loopback example: PCD and PICC communicating over in-memory channels.
//!
//! Demonstrates the full ISO14443 protocol flow:
//! 1. Activation (REQA → ATQA → anticollision → SELECT → SAK)
//! 2. RATS/ATS negotiation
//! 3. APDU exchange
//! 4. DESELECT
//!
//! Run with: `cargo run --example loopback --features std`

use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use iso14443::type_a::{
    Ats, Cid, Dxi, Frame, Fsci, Fsdi, PcdTransceiver, PiccTransceiver, Ta, Tb, Tc,
    activation::{activate, wakeup},
    pcd::Pcd,
    picc::{Picc, PiccConfig},
};

// ── Channel-based transceivers with frame logging ───────────────────────

#[derive(Debug)]
struct ChannelError;

/// PCD-side transceiver: sends a frame, waits for the PICC response.
struct ChannelPcd {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

impl PcdTransceiver for ChannelPcd {
    type Error = ChannelError;

    fn transceive(&mut self, frame: &Frame) -> Result<Vec<u8>, ChannelError> {
        let data = frame.data().to_vec();
        println!("  PCD  → PICC  [{:02x?}]", data);
        self.tx.send(data).map_err(|_| ChannelError)?;
        let resp = self.rx.recv().map_err(|_| ChannelError)?;
        println!("  PCD  ← PICC  [{:02x?}]", resp);
        Ok(resp)
    }

    fn try_enable_hw_crc(&mut self) -> Result<(), ChannelError> {
        Err(ChannelError) // no HW CRC in loopback
    }
}

/// PICC-side transceiver: waits for a frame from the PCD, sends response.
struct ChannelPicc {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

impl PiccTransceiver for ChannelPicc {
    type Error = ChannelError;

    fn receive(&mut self) -> Result<Vec<u8>, ChannelError> {
        self.rx.recv().map_err(|_| ChannelError)
    }

    fn send(&mut self, frame: &Frame) -> Result<(), ChannelError> {
        self.tx
            .send(frame.data().to_vec())
            .map_err(|_| ChannelError)
    }

    fn try_enable_hw_crc(&mut self) -> Result<(), ChannelError> {
        Err(ChannelError)
    }
}

/// Create a linked pair of PCD and PICC channel transceivers.
fn channel_pair() -> (ChannelPcd, ChannelPicc) {
    let (pcd_tx, picc_rx) = mpsc::channel();
    let (picc_tx, pcd_rx) = mpsc::channel();
    (
        ChannelPcd {
            tx: pcd_tx,
            rx: pcd_rx,
        },
        ChannelPicc {
            tx: picc_tx,
            rx: picc_rx,
        },
    )
}

// ── Main ────────────────────────────────────────────────────────────────

fn main() {
    let (mut pcd_side, mut picc_side) = channel_pair();

    // PICC thread: card emulation
    let picc_handle = thread::spawn(move || {
        let mut config = PiccConfig::new(iso14443::type_a::Uid::Triple([
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x13, 0x37,
        ]));
        // Small FSC (16 bytes) to demonstrate I-Block chaining
        config.enable_14443_4(Ats::new(
            Fsci::Fsc16,
            Ta::SAME_D_SUPP,
            Tb::default(),
            Tc::CID_SUPP,
        ));

        let mut picc = Picc::new(&mut picc_side, config);

        // Serve multiple sessions (activation → exchange → deselect → re-activation)
        for session in 1..=2 {
            picc.wait_for_activation().unwrap();
            println!("[PICC] Activation complete (session {session})");

            picc.wait_for_rats().unwrap();
            println!("[PICC] RATS/ATS complete");

            loop {
                match picc.receive_command() {
                    Ok(apdu) => {
                        println!(
                            "[PICC] APDU received ({} bytes): {:02x?}",
                            apdu.len(),
                            apdu.as_slice()
                        );
                        let mut resp: Vec<u8> = apdu.as_slice().to_vec();
                        resp.extend_from_slice(&[0x90, 0x00]);
                        picc.send_response(&resp).unwrap();
                    }
                    Err(iso14443::type_a::picc::PiccError::Deselected) => {
                        println!("[PICC] Deselected (now in HALT state)");
                        break;
                    }
                    Err(e) => {
                        println!("[PICC] Error: {e:?}");
                        return;
                    }
                }
            }
        }
    });

    // ── Session 1: REQA activation ─────────────────────────────────────

    println!("── Session 1: ISO14443-3A Activation (REQA) ────────────\n");

    let activation = activate(&mut pcd_side).unwrap();
    println!(
        "\n[PCD]  Activation complete — UID: {:02x?}, SAK: {:02x?}",
        activation.uid.as_slice(),
        activation.sak
    );

    println!("\n── ISO14443-4 RATS/ATS ─────────────────────────────────\n");

    let cid = Cid::new(0).unwrap();
    let (mut pcd, ats) = Pcd::connect(&mut pcd_side, Fsdi::Fsd16, cid).unwrap();
    println!(
        "\n[PCD]  Session established — FSC: {} bytes, FWI: {:?}",
        ats.format.fsci.fsc(),
        ats.tb
    );

    println!("\n── ISO14443-4 PPS (optional bit rate negotiation) ──────\n");

    pcd.pps(Dxi::Dx2, Dxi::Dx2).unwrap();
    println!("[PCD]  PPS complete — DR=2x, DS=2x");

    println!("\n── APDU Exchange (short, no chaining) ──────────────────\n");

    let short_apdu = [0x00, 0xA4, 0x04, 0x00];
    println!(
        "[PCD]  Sending APDU ({} bytes): {:02x?}",
        short_apdu.len(),
        short_apdu
    );
    let response = pcd.exchange(&short_apdu).unwrap();
    println!("[PCD]  Response APDU: {:02x?}", response.as_slice());

    println!("\n── APDU Exchange (long, with I-Block chaining) ────────\n");

    let long_apdu: Vec<u8> = (0x00..0x1E).collect();
    println!(
        "[PCD]  Sending APDU ({} bytes): {:02x?}",
        long_apdu.len(),
        long_apdu
    );
    let response = pcd.exchange(&long_apdu).unwrap();
    println!("[PCD]  Response APDU: {:02x?}", response.as_slice());

    println!("\n── DESELECT (PICC → HALT state) ────────────────────────\n");

    pcd.deselect().unwrap();
    println!("[PCD]  Session 1 closed, tag is now halted");

    // ── Session 2: WUPA re-activation ───────────────────────────────

    println!("\n── Session 2: ISO14443-3A Re-activation (WUPA) ────────\n");

    let activation = wakeup(&mut pcd_side).unwrap();
    println!(
        "\n[PCD]  Re-activated — UID: {:02x?}",
        activation.uid.as_slice(),
    );

    println!("\n── ISO14443-4 RATS/ATS ─────────────────────────────────\n");

    let (mut pcd, _ats) = Pcd::connect(&mut pcd_side, Fsdi::Fsd16, cid).unwrap();
    println!("\n[PCD]  Session 2 established");

    println!("\n── APDU Exchange (session 2) ────────────────────────────\n");

    let apdu = [0x00, 0xB0, 0x00, 0x00, 0x04];
    println!("[PCD]  Sending APDU: {:02x?}", apdu);
    let response = pcd.exchange(&apdu).unwrap();
    println!("[PCD]  Response APDU: {:02x?}", response.as_slice());

    println!("\n── DESELECT (session 2) ────────────────────────────────\n");

    pcd.deselect().unwrap();
    println!("[PCD]  Session 2 closed");

    picc_handle.join().unwrap();
    println!("\n── Done ────────────────────────────────────────────────");
}
