// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Bounds on the work an ISO14443-4 peer can make one exchange perform.
//!
//! Every field of a block that says "send me that again" or "wait longer"
//! is under the peer's control, and the protocol itself sets no ceiling on
//! how often it may say so. [`Limits`] adds one: each counter is reset at
//! the start of an exchange and, when a peer runs past it, the exchange
//! fails with [`TypeAError::LimitExceeded`] instead of looping or growing
//! the chain buffer forever.
//!
//! The defaults leave plenty of room for well-behaved cards; raise them
//! with [`crate::type_a::ProtocolHandler::with_limits`],
//! [`crate::type_a::Pcd::set_limits`] or
//! [`crate::type_a::Picc::set_limits`] if an application needs to.
//!
//! Note that these are *work* limits, not deadlines: the library is
//! synchronous and has no clock, so an overall timeout — and any
//! cancellation — belongs in the transceiver implementation.

use super::TypeAError;

/// Largest chain the default limits assemble from a peer's I-Blocks.
///
/// With `alloc` the chain grows on the heap, so the ceiling only has to be
/// generous; without it the chain is a fixed 1 KiB buffer and the cap
/// matches its capacity.
#[cfg(feature = "alloc")]
pub const DEFAULT_MAX_CHAIN_LEN: usize = 4096;
/// Largest chain the default limits assemble from a peer's I-Blocks.
#[cfg(not(feature = "alloc"))]
pub const DEFAULT_MAX_CHAIN_LEN: usize = 1024;

/// The bound a peer ran past.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// Blocks received in one exchange ([`Limits::max_frames`]).
    Frames,
    /// Consecutive requests to retransmit the same block
    /// ([`Limits::max_retransmissions`]).
    Retransmissions,
    /// Consecutive S(WTX) requests ([`Limits::max_consecutive_wtx`]).
    ConsecutiveWtx,
    /// S(WTX) requests in one exchange ([`Limits::max_total_wtx`]).
    TotalWtx,
    /// Malformed S(WTX): the INF field must be one byte and code a WTXM of
    /// 1 to 59 (§7.3).
    WtxValue,
    /// Assembled chained payload ([`Limits::max_chain_len`]).
    ChainLength,
    /// Received frame larger than the negotiated frame size.
    FrameSize,
}

impl From<Limit> for TypeAError {
    fn from(limit: Limit) -> Self {
        TypeAError::LimitExceeded(limit)
    }
}

/// Per-exchange work limits.
///
/// Counters reset at each exchange boundary — [`Pcd::exchange`] and
/// [`Picc::receive_command`] — so the limits bound one APDU exchange, not
/// the lifetime of a session.
///
/// [`Pcd::exchange`]: crate::type_a::Pcd::exchange
/// [`Picc::receive_command`]: crate::type_a::Picc::receive_command
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum number of blocks accepted from the peer in one exchange.
    ///
    /// Bounds the total work of an exchange whatever the peer sends, since
    /// each block costs it a frame. Default: 512.
    pub max_frames: u16,
    /// Maximum number of consecutive requests to retransmit the same block:
    /// R(NAK), or R(ACK) carrying the wrong block number. Default: 3.
    pub max_retransmissions: u8,
    /// Maximum number of S(WTX) requests in a row, with no block carrying
    /// the exchange forward in between. Default: 8.
    pub max_consecutive_wtx: u8,
    /// Maximum number of S(WTX) requests in one exchange. Default: 32.
    pub max_total_wtx: u16,
    /// Maximum number of payload bytes assembled from a chain of I-Blocks.
    /// Default: [`DEFAULT_MAX_CHAIN_LEN`].
    pub max_chain_len: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frames: 512,
            max_retransmissions: 3,
            max_consecutive_wtx: 8,
            max_total_wtx: 32,
            max_chain_len: DEFAULT_MAX_CHAIN_LEN,
        }
    }
}

/// Per-exchange counters checked against [`Limits`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Counters {
    pub frames: u16,
    pub retransmissions: u8,
    pub consecutive_wtx: u8,
    pub total_wtx: u16,
}

impl Counters {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Clear the counters that only bound a *run* of unproductive blocks;
    /// called whenever a block actually carries the exchange forward.
    pub fn note_progress(&mut self) {
        self.retransmissions = 0;
        self.consecutive_wtx = 0;
    }
}
