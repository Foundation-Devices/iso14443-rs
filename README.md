<!--
SPDX-FileCopyrightText: © 2025 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# iso14443

[![Crates.io](https://img.shields.io/crates/v/iso14443.svg?maxAge=2592000)](https://crates.io/crates/iso14443)

Rust library to manipulate ISO/IEC 14443 data.

## Fontionalities

- [x] Type-A
    - [x] iso14443-3: REQA/WUPA/ATQA/ANTICOLLISION/SELECT/SAK/HLTA
    - [x] CRC_A checks
    - [x] iso14443-4: RATS/ATS/PPS
    - [x] iso14443-4: PCB (Protocol Control Byte)
    - [x] iso14443-4: Block format (I-block, R-block, S-block)
    - [x] iso14443-4: Block chaining
    - [x] iso14443-4: Protocol state machine
- [ ] Type-B

## Example Usage

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
