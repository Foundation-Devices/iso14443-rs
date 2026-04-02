//! # iso14443
//!
//! Rust implementation of the ISO/IEC 14443 NFC/RFID proximity card protocol.
//!
//! Covers both sides of the communication:
//! - **PCD** (reader): activate tags, negotiate parameters, exchange APDUs
//! - **PICC** (card emulation): respond to activation, serve APDUs
//!
//! ## Architecture
//!
//! The library is organized around two hardware traits and a shared protocol core:
//!
//! - [`type_a::PcdTransceiver`] — implement for your reader hardware (atomic send+receive)
//! - [`type_a::PiccTransceiver`] — implement for card emulation hardware (separate receive/send)
//! - [`type_a::ProtocolHandler`] — generic block protocol state machine, used by both sides
//!
//! ## Quick start (PCD)
//!
//! ```rust,ignore
//! use iso14443::type_a::{activation::activate, pcd::Pcd, Cid, Fsdi};
//!
//! let activation = activate(&mut t).map_err(|e| format!("{e:?}"))?;
//! if activation.sak.iso14443_4_compliant {
//!     let cid = Cid::new(0).unwrap();
//!     let (mut pcd, _ats) = Pcd::connect(&mut t, Fsdi::Fsd256, cid)
//!         .map_err(|e| format!("{e:?}"))?;
//!     let resp = pcd.exchange(&[0x00, 0xA4, 0x04, 0x00])
//!         .map_err(|e| format!("{e:?}"))?;
//!     pcd.deselect().map_err(|e| format!("{e:?}"))?;
//! }
//! ```
//!
//! ## Features
//!
//! - `alloc` — use `Vec` instead of `heapless::Vec` for frame buffers
//! - `std` — implies `alloc`, enables `Duration`-based timing calculations
//!
//! `#![no_std]` by default (uses `heapless` with fixed-size buffers).

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod type_a;
