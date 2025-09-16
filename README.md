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
    - [x] iso14443-4: RATS/ATS
    - [ ] iso14443-4: PPSS/PPSR
- [ ] Type-B

## Example Usage

An example is provided to parse raw data from the ISO14443 protocol:

```bash
$ cargo run --example cli_parser -- e050bca5 057780800046ab
cmd: Rats(RatsParam(Fsd64, Cid(Bounded(00))))
ans: Ats(Ats { length: 05, format: Format { fsc: 80, ta_transmitted: true, tb_transmitted: true, tc_transmitted: true }, ta: Ta(SAME_D_SUPP), tb: Tb { sfgi: Sfgi(00), fwi: Fwi(08) }, tc: Tc(0x0), historical_bytes: [] })
```

The first argument is the command sent by PCD to PICC in hexadecimal format.
The second argument is the answer from PICC to PCD.
