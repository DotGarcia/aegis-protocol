//! Schema and message identifiers.

use core::fmt;

use crate::{Error, Result};

/// A compact 128-bit schema fingerprint.
///
/// Production deployments should derive this from a canonical schema
/// representation using a cryptographic hash. The IDL crate also exposes a
/// deterministic development fingerprint for tests and local tooling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SchemaId([u8; 16]);

impl SchemaId {
    /// Creates a schema identifier from raw bytes.
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the raw schema identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// A zero schema id used only for testing or placeholders.
    pub const fn zero() -> Self {
        Self([0; 16])
    }

    /// Builds an experimental deterministic identifier from canonical schema bytes.
    ///
    /// This is **not** a cryptographic hash. It is provided only so examples and
    /// tests can derive stable ids without extra dependencies. Production
    /// implementations should use a cryptographic schema fingerprint.
    pub fn experimental_from_canonical(input: &[u8]) -> Self {
        let mut a: u64 = 0xcbf2_9ce4_8422_2325;
        let mut b: u64 = 0x9e37_79b9_7f4a_7c15;
        for byte in input {
            a ^= *byte as u64;
            a = a.wrapping_mul(0x0000_0100_0000_01b3);
            b ^= a.rotate_left(13) ^ (*byte as u64);
            b = b.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        }
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&a.to_le_bytes());
        out[8..].copy_from_slice(&b.to_le_bytes());
        Self(out)
    }

    /// Parses a 32-character lowercase or uppercase hexadecimal schema id.
    pub fn from_hex(input: &str) -> Result<Self> {
        let bytes = input.as_bytes();
        if bytes.len() != 32 {
            return Err(Error::MalformedFrame);
        }
        let mut out = [0u8; 16];
        let mut i = 0;
        while i < 16 {
            let hi = hex_value(bytes[i * 2])?;
            let lo = hex_value(bytes[i * 2 + 1])?;
            out[i] = (hi << 4) | lo;
            i += 1;
        }
        Ok(Self(out))
    }
}

impl fmt::Display for SchemaId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

fn hex_value(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::MalformedFrame),
    }
}

/// Stable numeric message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageType(u32);

impl MessageType {
    /// Creates a message type.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the numeric message type.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}
