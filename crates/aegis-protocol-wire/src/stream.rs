//! Stream and flow-control wire helpers.

use aegis_protocol_core::{Error, Result};

/// Stream signal codes used by realtime profiles.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamSignal {
    /// Open a stream.
    Open = 0x01,
    /// Carry stream data.
    Data = 0x02,
    /// Increase receive window.
    WindowUpdate = 0x03,
    /// Pause a stream.
    Pause = 0x04,
    /// Resume a paused stream.
    Resume = 0x05,
    /// Reset a stream.
    Reset = 0x06,
    /// Gracefully close a stream.
    Close = 0x07,
    /// Send heartbeat.
    Heartbeat = 0x08,
}

/// Minimal flow-control update payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowUpdate {
    /// Stream slot being updated.
    pub stream_slot: u32,
    /// Additional bytes the peer may send.
    pub additional_bytes: u32,
}

impl WindowUpdate {
    /// Encoded length of a window update.
    pub const LEN: usize = 8;

    /// Encodes this update into an 8-byte buffer.
    pub fn encode(self, out: &mut [u8]) -> Result<usize> {
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0..4].copy_from_slice(&self.stream_slot.to_le_bytes());
        out[4..8].copy_from_slice(&self.additional_bytes.to_le_bytes());
        Ok(Self::LEN)
    }

    /// Decodes this update from bytes.
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < Self::LEN {
            return Err(Error::UnexpectedEof);
        }
        Ok(Self {
            stream_slot: u32::from_le_bytes([input[0], input[1], input[2], input[3]]),
            additional_bytes: u32::from_le_bytes([input[4], input[5], input[6], input[7]]),
        })
    }
}
