//! Flow-control frame helpers.

use aegis_protocol_core::{Error, Result, StreamSlot};

/// Flow-control operation.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowKind {
    /// Increase the receive window for a stream.
    WindowUpdate = 1,
    /// Ask the sender to pause a stream.
    StreamPause = 2,
    /// Resume a paused stream.
    StreamResume = 3,
    /// Drain a connection gracefully.
    Drain = 4,
    /// Signal overload.
    Overload = 5,
}

impl FlowKind {
    /// Converts a raw byte into a flow kind.
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::WindowUpdate),
            2 => Ok(Self::StreamPause),
            3 => Ok(Self::StreamResume),
            4 => Ok(Self::Drain),
            5 => Ok(Self::Overload),
            _ => Err(Error::MalformedFrame),
        }
    }
}

/// Compact flow-control frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowControlFrame {
    /// Flow-control operation.
    pub kind: FlowKind,
    /// Stream affected by this operation.
    pub stream_slot: StreamSlot,
    /// Number of bytes, reason code or profile-specific value.
    pub value: u64,
}

impl FlowControlFrame {
    /// Encoded flow-control frame length.
    pub const LEN: usize = 13;

    /// Encodes the frame into `out`.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.kind as u8;
        out[1..5].copy_from_slice(&self.stream_slot.get().to_le_bytes());
        out[5..13].copy_from_slice(&self.value.to_le_bytes());
        Ok(Self::LEN)
    }

    /// Decodes a flow-control frame.
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < Self::LEN {
            return Err(Error::UnexpectedEof);
        }
        Ok(Self {
            kind: FlowKind::from_u8(input[0])?,
            stream_slot: StreamSlot::new(u32::from_le_bytes([
                input[1], input[2], input[3], input[4],
            ])),
            value: u64::from_le_bytes([
                input[5], input[6], input[7], input[8], input[9], input[10], input[11], input[12],
            ]),
        })
    }
}
