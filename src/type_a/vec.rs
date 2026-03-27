// SPDX-FileCopyrightText: © 2025 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::TypeAError;

#[cfg(feature = "alloc")]
pub type FrameVec = alloc::vec::Vec<u8>;
#[cfg(not(feature = "alloc"))]
pub type FrameVec = heapless::Vec<u8, 256>;

#[cfg(feature = "alloc")]
pub type ChainVec = alloc::vec::Vec<u8>;
#[cfg(not(feature = "alloc"))]
pub type ChainVec = heapless::Vec<u8, 1024>;

pub(crate) trait VecExt<T> {
    fn try_push(&mut self, val: T) -> Result<(), TypeAError>;
    fn try_extend(&mut self, slice: &[T]) -> Result<(), TypeAError>
    where
        T: Clone;
}

#[cfg(feature = "alloc")]
impl<T: Clone> VecExt<T> for alloc::vec::Vec<T> {
    fn try_push(&mut self, val: T) -> Result<(), TypeAError> {
        self.push(val);
        Ok(())
    }
    fn try_extend(&mut self, slice: &[T]) -> Result<(), TypeAError> {
        self.extend_from_slice(slice);
        Ok(())
    }
}

#[cfg(not(feature = "alloc"))]
impl<T: Clone, const N: usize> VecExt<T> for heapless::Vec<T, N> {
    fn try_push(&mut self, val: T) -> Result<(), TypeAError> {
        self.push(val).map_err(|_| TypeAError::BufferFull)
    }
    fn try_extend(&mut self, slice: &[T]) -> Result<(), TypeAError> {
        self.extend_from_slice(slice)
            .map_err(|_| TypeAError::BufferFull)
    }
}
