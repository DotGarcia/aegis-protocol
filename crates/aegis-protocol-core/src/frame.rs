//! Frame and transport related enums.

use core::convert::TryFrom;

use crate::{Error, Result};

/// High-level frame kind.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// Control-plane frame: handshake, errors, negotiation and management.
    Control = 0x01,
    /// Hot-path application data frame.
    Data = 0x02,
    /// Stream data frame.
    Stream = 0x03,
    /// Flow-control frame.
    Flow = 0x04,
    /// Error frame.
    Error = 0x7f,
}

impl TryFrom<u8> for FrameKind {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Self::Control),
            0x02 => Ok(Self::Data),
            0x03 => Ok(Self::Stream),
            0x04 => Ok(Self::Flow),
            0x7f => Ok(Self::Error),
            _ => Err(Error::UnknownFrameKind),
        }
    }
}

/// Security mode negotiated for a session or envelope.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityMode {
    /// Security is bound to a transport such as TLS 1.3 or QUIC.
    TransportBound = 0,
    /// Every message carries a separate authentication envelope.
    MessageEnvelope = 1,
}

/// Transport profile used by the protocol.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProfile {
    /// QUIC bidirectional or unidirectional stream.
    QuicStream = 0,
    /// QUIC datagram.
    QuicDatagram = 1,
    /// TCP secured by TLS.
    TlsTcp = 2,
    /// Local inter-process communication.
    Ipc = 3,
    /// Brokered or queued message delivery.
    BrokeredMessage = 4,
    /// Shared-memory transport.
    SharedMemory = 5,
}
