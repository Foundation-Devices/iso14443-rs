// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! ISO14443-3A tag activation: REQA → anticollision cascade → SELECT.

use super::{
    Command, Frame, PcdTransceiver, Sak, TypeAError,
    anticol_select::{NumberOfValidBits, SEL_CL1, SEL_CL2, SEL_CL3},
    atqa::AtqA,
    crc::append_crc_a,
    vec::{FrameVec, VecExt},
};

/// Error during tag activation.
#[derive(Debug)]
pub enum ActivationError<E> {
    /// The transceiver returned an error.
    PcdTransceiver(E),
    /// ISO14443 protocol violation (invalid BCC, CRC, length, etc.).
    Protocol(TypeAError),
}

impl<E> From<TypeAError> for ActivationError<E> {
    fn from(e: TypeAError) -> Self {
        ActivationError::Protocol(e)
    }
}

/// Result of a successful ISO14443-3A tag activation.
#[derive(Debug)]
pub struct Activation {
    /// ATQA response from the tag.
    pub atqa: AtqA,
    /// Final SAK indicating tag capabilities.
    pub sak: Sak,
    /// Reconstructed UID (4, 7, or 10 bytes).
    pub uid: FrameVec,
}

/// Perform ISO14443-3A tag detection, anticollision, and activation.
///
/// Sends REQA, then resolves the full UID through up to 3 cascade levels
/// (supporting 4, 7, and 10-byte UIDs per ISO14443-3).
pub fn activate<T: PcdTransceiver>(t: &mut T) -> Result<Activation, ActivationError<T::Error>> {
    do_activate(t, Command::ReqA)
}

/// Re-activate a halted tag using WUPA.
///
/// Same as [`activate`] but sends WUPA (0x52) instead of REQA (0x26),
/// which wakes tags in the HALT state. Use after DESELECT or HLTA.
pub fn wakeup<T: PcdTransceiver>(t: &mut T) -> Result<Activation, ActivationError<T::Error>> {
    do_activate(t, Command::WupA)
}

fn do_activate<T: PcdTransceiver>(
    t: &mut T,
    req: Command,
) -> Result<Activation, ActivationError<T::Error>> {
    let hw_crc = t.try_enable_hw_crc().is_ok();

    let frame = req.to_frame()?;
    let resp = t
        .transceive(&frame)
        .map_err(ActivationError::PcdTransceiver)?;
    let atqa = AtqA::try_from(resp.as_slice())?;

    // Cascade level 1
    let uid_cl1 = do_anticollision(t, SEL_CL1)?;
    let sak = do_select(t, SEL_CL1, &uid_cl1, hw_crc)?;
    if sak.uid_complete {
        return Ok(build_activation(atqa, sak, &[&uid_cl1], 1)?);
    }

    // Cascade level 2
    let uid_cl2 = do_anticollision(t, SEL_CL2)?;
    let sak = do_select(t, SEL_CL2, &uid_cl2, hw_crc)?;
    if sak.uid_complete {
        return Ok(build_activation(atqa, sak, &[&uid_cl1, &uid_cl2], 2)?);
    }

    // Cascade level 3
    let uid_cl3 = do_anticollision(t, SEL_CL3)?;
    let sak = do_select(t, SEL_CL3, &uid_cl3, hw_crc)?;
    if sak.uid_complete {
        return Ok(build_activation(
            atqa,
            sak,
            &[&uid_cl1, &uid_cl2, &uid_cl3],
            3,
        )?);
    }

    Err(ActivationError::Protocol(TypeAError::Other))
}

/// Send anticollision command, return 5-byte UID+BCC after BCC validation.
fn do_anticollision<T: PcdTransceiver>(
    t: &mut T,
    sel: u8,
) -> Result<[u8; 5], ActivationError<T::Error>> {
    let nvb = u8::from(&NumberOfValidBits::anticollision());
    let mut data = FrameVec::new();
    data.try_push(sel)?;
    data.try_push(nvb)?;
    let resp = t
        .transceive(&Frame::BitOriented(data))
        .map_err(ActivationError::PcdTransceiver)?;
    if resp.len() != 5 {
        return Err(ActivationError::Protocol(TypeAError::InvalidLength));
    }
    // Validate BCC (XOR of all 5 bytes must be 0)
    if resp[0] ^ resp[1] ^ resp[2] ^ resp[3] ^ resp[4] != 0 {
        return Err(ActivationError::Protocol(TypeAError::InvalidBcc));
    }
    let mut uid = [0u8; 5];
    uid.copy_from_slice(&resp);
    Ok(uid)
}

/// Send SELECT command, return parsed SAK.
fn do_select<T: PcdTransceiver>(
    t: &mut T,
    sel: u8,
    uid_bcc: &[u8; 5],
    hw_crc: bool,
) -> Result<Sak, ActivationError<T::Error>> {
    let nvb = u8::from(&NumberOfValidBits::select());
    let mut data = FrameVec::new();
    data.try_push(sel)?;
    data.try_push(nvb)?;
    data.try_extend(uid_bcc)?;

    if hw_crc {
        // Hardware appends CRC on TX and strips it from RX
        let resp = t
            .transceive(&Frame::Standard(data))
            .map_err(ActivationError::PcdTransceiver)?;
        if resp.len() != 1 {
            return Err(ActivationError::Protocol(TypeAError::InvalidLength));
        }
        Ok(Sak::from_raw(resp[0]))
    } else {
        // Software CRC: append CRC_A to TX data, validate CRC on RX
        let cmd = append_crc_a(&data)?;
        let resp = t
            .transceive(&Frame::Standard(cmd))
            .map_err(ActivationError::PcdTransceiver)?;
        Ok(Sak::try_from(resp.as_slice())?)
    }
}

/// Reconstruct the full UID from cascade level responses.
///
/// Per ISO14443-3:
/// - 1 level (4-byte UID): uid_cl1[0..4]
/// - 2 levels (7-byte UID): uid_cl1[1..4] ++ uid_cl2[0..4] (skip cascade
///   tag 0x88)
/// - 3 levels (10-byte UID): uid_cl1[1..4] ++ uid_cl2[1..4] ++ uid_cl3[0..4]
fn build_activation(
    atqa: AtqA,
    sak: Sak,
    uid_cls: &[&[u8; 5]],
    levels: usize,
) -> Result<Activation, TypeAError> {
    let mut uid = FrameVec::new();
    for (i, cl) in uid_cls.iter().enumerate() {
        if i < levels - 1 {
            // Intermediate level: skip cascade tag (0x88), take bytes 1..4
            uid.try_extend(&cl[1..4])?;
        } else {
            // Final level: take bytes 0..4 (no cascade tag)
            uid.try_extend(&cl[0..4])?;
        }
    }
    Ok(Activation { atqa, sak, uid })
}
