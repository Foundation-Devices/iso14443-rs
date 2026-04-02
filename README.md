<!--
SPDX-FileCopyrightText: © 2025 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# iso14443

[![Crates.io](https://img.shields.io/crates/v/iso14443.svg?maxAge=2592000)](https://crates.io/crates/iso14443)

Rust library to manipulate ISO/IEC 14443 data.

## Functionalities

- [x] Type-A
    - [x] iso14443-3: REQA/WUPA/ATQA/ANTICOLLISION/SELECT/SAK/HLTA
    - [x] iso14443-3: CRC_A checks (hardware-accelerated or software)
    - [x] iso14443-3: PCD activation with anticollision cascade (4/7/10-byte UIDs)
    - [x] iso14443-3: PICC activation responder (ATQA, anticollision, SAK)
    - [x] iso14443-3: WUPA re-activation of halted tags
    - [x] iso14443-4: RATS/ATS/PPS (both PCD and PICC sides)
    - [x] iso14443-4: PCB (Protocol Control Byte)
    - [x] iso14443-4: Block format (I-block, R-block, S-block)
    - [x] iso14443-4: PCD transport layer (APDU exchange, chaining, WTX, error recovery, DESELECT)
    - [x] iso14443-4: PICC transport layer (card emulation, chaining, PPS, DESELECT → HALT)
    - [x] iso14443-4: Generic block protocol handler (reusable for PCD and PICC)
- [ ] Type-B

## Usage

```rust
use iso14443::type_a::{
    activation::{activate, ActivationError},
    pcd::{Pcd, PcdError},
    vec::FrameVec,
    Cid, Frame, Fsdi, PcdTransceiver,
};

/// Dummy PCD transceiver — replace with your real hardware driver
/// (e.g. SPI to an NXP PN532 or ST25R3916).
struct MyTransceiver;

#[derive(Debug)]
struct MyError;

impl PcdTransceiver for MyTransceiver {
    type Error = MyError;

    fn transceive(&mut self, _frame: &Frame) -> Result<FrameVec, MyError> {
        // Send frame bytes over SPI/I2C/UART, return the PICC response.
        todo!("implement for your hardware")
    }

    fn try_enable_hw_crc(&mut self) -> Result<(), MyError> {
        // Enable hardware CRC if the chip supports it.
        // Return Err to fall back to software CRC.
        Err(MyError)
    }
}

fn talk_to_card(t: &mut MyTransceiver) -> Result<(), Box<dyn std::error::Error>> {
    // ISO14443-3A: detect tag, resolve UID
    let activation = activate(t).map_err(|e| format!("{e:?}"))?;
    println!("UID: {:02x?}", activation.uid.as_slice());

    // Only proceed to ISO14443-4 if the tag supports it
    if !activation.sak.iso14443_4_compliant {
        println!("Tag does not support ISO14443-4");
        return Ok(());
    }

    // ISO14443-4: RATS/ATS negotiation, open a session
    let cid = Cid::new(0).unwrap();
    let (mut pcd, ats) = Pcd::connect(t, Fsdi::Fsd256, cid)
        .map_err(|e| format!("{e:?}"))?;
    println!("ATS: {ats:?}");

    // Exchange an APDU (e.g. SELECT application)
    let select_apdu = [0x00, 0xA4, 0x04, 0x00, 0x07,
        0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00];
    let response = pcd.exchange(&select_apdu)
        .map_err(|e| format!("{e:?}"))?;
    println!("Response: {:02x?}", response.as_slice());

    // Clean up
    pcd.deselect().map_err(|e| format!("{e:?}"))?;
    Ok(())
}
```

## Loopback Example

A full PCD↔PICC loopback demonstrates the entire protocol over in-memory channels:

```bash
$ cargo run --example loopback --features std
```

Exercises: triple-cascade UID (10 bytes), RATS/ATS, PPS negotiation, short and long APDU exchange with I-Block chaining, DESELECT → HALT, and WUPA re-activation for a second session.

## CLI Parser

An example is provided to parse raw data from the ISO14443 protocol:

```bash
$ cargo run --example cli_parser -- -c e050bca5 -a 057780800046ab
command: Rats(
    RatsParam(fsdi: 5 -> FSD(64 bytes), cid: 0),
)
answer: Ats(
    Ats {
        length: 0x5,
        format: Format {
            fsci: 7 -> FSC(128 bytes),
            ta_transmitted: true,
            tb_transmitted: true,
            tc_transmitted: true,
        },
        ta: Ta(
            SAME_D_SUPP,
        ),
        tb: Tb {
            sfgi: 0 -> SFGT(0ns),
            fwi: 8 -> FWT(77.312ms),
        },
        tc: Tc(
            0x0,
        ),
        historical_bytes: [],
    },
)
```
