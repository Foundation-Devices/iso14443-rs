// SPDX-FileCopyrightText: © 2025 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::pcb::Pcb;
use super::{Block, BlockType, RBlockSubtype, SBlockSubtype, TypeAError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolState {
    Idle,
    WaitingForAck {
        block_number: u8,
    },
    ReceivingChain {
        block_number: u8,
        data: Vec<u8>,
    },
    TransmittingChain {
        block_number: u8,
        data: Vec<u8>,
        position: usize,
    },
    Error(TypeAError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockChain {
    pub blocks: Vec<Block>,
    pub complete_data: Vec<u8>,
}

impl Default for BlockChain {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockChain {
    pub fn new() -> Self {
        Self {
            blocks: Vec::new(),
            complete_data: Vec::new(),
        }
    }

    pub fn add_block(&mut self, block: Block) -> Result<(), TypeAError> {
        match block.block_type() {
            BlockType::IBlock => {
                if block.is_chaining() {
                    // This is a chained block
                    self.blocks.push(block.clone());
                    self.complete_data.extend_from_slice(&block.payload);
                    Ok(())
                } else {
                    // This is the final block
                    self.blocks.push(block.clone());
                    self.complete_data.extend_from_slice(&block.payload);
                    Ok(())
                }
            }
            _ => Err(TypeAError::Other),
        }
    }

    pub fn is_complete(&self) -> bool {
        if self.blocks.is_empty() {
            return false;
        }

        // Check if the last block is not chaining
        if let Some(last_block) = self.blocks.last() {
            !last_block.is_chaining()
        } else {
            false
        }
    }

    pub fn reset(&mut self) {
        self.blocks.clear();
        self.complete_data.clear();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolHandler {
    state: ProtocolState,
    block_chain: BlockChain,
    current_block_number: u8,
}

impl ProtocolHandler {
    pub fn new() -> Self {
        Self {
            state: ProtocolState::Idle,
            block_chain: BlockChain::new(),
            current_block_number: 0,
        }
    }

    pub fn state(&self) -> &ProtocolState {
        &self.state
    }

    pub fn reset(&mut self) {
        self.state = ProtocolState::Idle;
        self.block_chain.reset();
        self.current_block_number = 0;
    }

    pub fn send_iblock(&mut self, payload: Vec<u8>, chaining: bool) -> Result<Block, TypeAError> {
        let pcb = Pcb::new(BlockType::IBlock)
            .with_block_number(self.current_block_number)
            .with_chaining(chaining);

        let block = Block::new(pcb).with_payload(payload);

        if chaining {
            self.state = ProtocolState::TransmittingChain {
                block_number: self.current_block_number,
                data: block.payload.clone(),
                position: 0,
            };
        } else {
            self.state = ProtocolState::WaitingForAck {
                block_number: self.current_block_number,
            };
        }

        self.current_block_number = 1 - self.current_block_number; // Toggle block number
        Ok(block)
    }

    pub fn send_rblock(&mut self, ack: bool) -> Result<Block, TypeAError> {
        let subtype = if ack {
            RBlockSubtype::Ack
        } else {
            RBlockSubtype::Nak
        };
        let pcb = Pcb::new(BlockType::RBlock)
            .with_block_number(self.current_block_number)
            .with_r_subtype(subtype);

        let block = Block::new(pcb);

        self.state = ProtocolState::Idle;
        Ok(block)
    }

    pub fn send_sblock(
        &mut self,
        subtype: SBlockSubtype,
        payload: Vec<u8>,
    ) -> Result<Block, TypeAError> {
        let pcb = Pcb::new(BlockType::SBlock).with_s_subtype(subtype);
        let block = Block::new(pcb).with_payload(payload);

        self.state = ProtocolState::Idle;
        Ok(block)
    }

    pub fn receive_block(&mut self, block: Block) -> Result<Option<Vec<u8>>, TypeAError> {
        match &self.state {
            ProtocolState::Idle => self.handle_idle_receive(block),
            ProtocolState::WaitingForAck { block_number } => {
                self.handle_waiting_for_ack(block, *block_number)
            }
            ProtocolState::ReceivingChain { block_number, data } => {
                self.handle_receiving_chain(block, *block_number, data.clone())
            }
            ProtocolState::TransmittingChain { .. } => {
                // Should not receive blocks while transmitting
                Err(TypeAError::Other)
            }
            ProtocolState::Error(_) => Err(TypeAError::Other),
        }
    }

    fn handle_idle_receive(&mut self, block: Block) -> Result<Option<Vec<u8>>, TypeAError> {
        match block.block_type() {
            BlockType::IBlock => {
                if block.is_chaining() {
                    // Start receiving a chain
                    self.block_chain.add_block(block.clone())?;
                    self.state = ProtocolState::ReceivingChain {
                        block_number: block.block_number(),
                        data: block.payload.clone(),
                    };
                    Ok(None)
                } else {
                    // Single block message
                    Ok(Some(block.payload))
                }
            }
            BlockType::RBlock => {
                // Unexpected R-block in idle state
                Err(TypeAError::Other)
            }
            BlockType::SBlock => {
                // Handle S-block (like WTX, DESELECT)
                match block.pcb.s_subtype {
                    Some(SBlockSubtype::Deselect) => {
                        self.reset();
                        Ok(None)
                    }
                    Some(SBlockSubtype::Wtx) => {
                        // Handle waiting time extension
                        Ok(None)
                    }
                    _ => Err(TypeAError::Other),
                }
            }
        }
    }

    fn handle_waiting_for_ack(
        &mut self,
        block: Block,
        expected_block_number: u8,
    ) -> Result<Option<Vec<u8>>, TypeAError> {
        match block.block_type() {
            BlockType::RBlock => {
                if block.block_number() == expected_block_number {
                    match block.pcb.r_subtype {
                        Some(RBlockSubtype::Ack) => {
                            self.state = ProtocolState::Idle;
                            Ok(None) // ACK received, transmission successful
                        }
                        Some(RBlockSubtype::Nak) => {
                            self.state = ProtocolState::Error(TypeAError::Other);
                            Err(TypeAError::Other) // NAK received, transmission failed
                        }
                        None => Err(TypeAError::Other),
                    }
                } else {
                    Err(TypeAError::Other) // Wrong block number
                }
            }
            _ => Err(TypeAError::Other),
        }
    }

    fn handle_receiving_chain(
        &mut self,
        block: Block,
        expected_block_number: u8,
        mut data: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, TypeAError> {
        match block.block_type() {
            BlockType::IBlock => {
                if block.block_number() == expected_block_number {
                    data.extend_from_slice(&block.payload);

                    if block.is_chaining() {
                        // More blocks to come
                        self.state = ProtocolState::ReceivingChain {
                            block_number: 1 - expected_block_number,
                            data,
                        };
                        Ok(None)
                    } else {
                        // Chain complete
                        data.extend_from_slice(&block.payload);
                        self.state = ProtocolState::Idle;
                        Ok(Some(data))
                    }
                } else {
                    Err(TypeAError::Other) // Wrong block number
                }
            }
            _ => Err(TypeAError::Other),
        }
    }
}

impl Default for ProtocolHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_handler_initialization() {
        let handler = ProtocolHandler::new();
        assert_eq!(handler.state(), &ProtocolState::Idle);
    }

    #[test]
    fn test_send_single_iblock() {
        let mut handler = ProtocolHandler::new();
        let payload = vec![0x01, 0x02, 0x03];

        let block = handler.send_iblock(payload.clone(), false).unwrap();

        assert_eq!(block.block_type(), BlockType::IBlock);
        assert_eq!(block.payload, payload);
        assert!(!block.is_chaining());
        assert_eq!(
            handler.state(),
            &ProtocolState::WaitingForAck { block_number: 0 }
        );
    }

    #[test]
    fn test_send_chained_iblock() {
        let mut handler = ProtocolHandler::new();
        let payload = vec![0x01, 0x02, 0x03];

        let block = handler.send_iblock(payload.clone(), true).unwrap();

        assert_eq!(block.block_type(), BlockType::IBlock);
        assert_eq!(block.payload, payload);
        assert!(block.is_chaining());
        assert!(matches!(
            handler.state(),
            ProtocolState::TransmittingChain { .. }
        ));
    }

    #[test]
    fn test_send_rblock_ack() {
        let mut handler = ProtocolHandler::new();
        let block = handler.send_rblock(true).unwrap();

        assert_eq!(block.block_type(), BlockType::RBlock);
        assert_eq!(block.pcb.r_subtype, Some(RBlockSubtype::Ack));
        assert_eq!(handler.state(), &ProtocolState::Idle);
    }

    #[test]
    fn test_send_rblock_nak() {
        let mut handler = ProtocolHandler::new();
        let block = handler.send_rblock(false).unwrap();

        assert_eq!(block.block_type(), BlockType::RBlock);
        assert_eq!(block.pcb.r_subtype, Some(RBlockSubtype::Nak));
        assert_eq!(handler.state(), &ProtocolState::Idle);
    }

    #[test]
    fn test_send_sblock_wtx() {
        let mut handler = ProtocolHandler::new();
        let payload = vec![0x10]; // WTX parameter
        let block = handler.send_sblock(SBlockSubtype::Wtx, payload).unwrap();

        assert_eq!(block.block_type(), BlockType::SBlock);
        assert_eq!(block.pcb.s_subtype, Some(SBlockSubtype::Wtx));
        assert_eq!(handler.state(), &ProtocolState::Idle);
    }

    #[test]
    fn test_receive_single_iblock() {
        let mut handler = ProtocolHandler::new();
        let payload = vec![0x01, 0x02, 0x03];
        let block = Block::new(Pcb::new(BlockType::IBlock)).with_payload(payload.clone());

        let result = handler.receive_block(block).unwrap();
        assert_eq!(result, Some(payload));
        assert_eq!(handler.state(), &ProtocolState::Idle);
    }

    #[test]
    fn test_block_chain_operations() {
        let mut chain = BlockChain::new();

        // Add first chained block
        let block1 = Block::new(Pcb::new(BlockType::IBlock).with_chaining(true))
            .with_payload(vec![0x01, 0x02]);
        chain.add_block(block1).unwrap();
        assert!(!chain.is_complete());

        // Add final block
        let block2 = Block::new(Pcb::new(BlockType::IBlock).with_chaining(false))
            .with_payload(vec![0x03, 0x04]);
        chain.add_block(block2).unwrap();
        assert!(chain.is_complete());

        assert_eq!(chain.complete_data, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_protocol_reset() {
        let mut handler = ProtocolHandler::new();

        // Put handler in some state
        let _ = handler.send_iblock(vec![0x01], true);

        // Reset
        handler.reset();
        assert_eq!(handler.state(), &ProtocolState::Idle);
        assert_eq!(handler.current_block_number, 0);
    }
}
