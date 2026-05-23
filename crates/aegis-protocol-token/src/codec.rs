//! Internal deterministic token codec helpers.

use alloc::string::String;
use alloc::vec::Vec;

use aegis_protocol_core::varint::{decode_u64, encode_u64, encoded_len_u64, MAX_U64_VARINT_LEN};

use crate::{Result, TokenError};

/// Maximum bytes accepted for a whole encoded ACT token.
pub const MAX_TOKEN_BYTES: usize = 64 * 1024;
/// Maximum bytes accepted for a key identifier.
pub const MAX_KEY_ID_BYTES: usize = 128;
/// Maximum bytes accepted for issuer, subject, audience or issuer hint strings.
pub const MAX_IDENTITY_BYTES: usize = 256;
/// Maximum bytes accepted for a capability name.
pub const MAX_CAPABILITY_NAME_BYTES: usize = 256;
/// Maximum bytes accepted for a capability scope blob.
pub const MAX_SCOPE_BYTES: usize = 4096;
/// Maximum capabilities in a token.
pub const MAX_CAPABILITIES: usize = 64;
/// Maximum message type allow-list entries per capability.
pub const MAX_MESSAGES_PER_CAPABILITY: usize = 128;

/// Appends an unsigned varint to an output vector.
pub fn push_varint(out: &mut Vec<u8>, value: u64) {
    let mut buf = [0u8; MAX_U64_VARINT_LEN];
    let len = encode_u64(value, &mut buf).expect("fixed varint buffer is large enough");
    out.extend_from_slice(&buf[..len]);
}

/// Returns the encoded varint length.
pub const fn varint_len(value: u64) -> usize {
    encoded_len_u64(value)
}

/// Appends a length-prefixed byte string.
pub fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    push_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// Appends a length-prefixed UTF-8 string.
pub fn push_string(out: &mut Vec<u8>, value: &str) {
    push_bytes(out, value.as_bytes());
}

/// Appends a little-endian u16.
pub fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Appends a little-endian u32.
pub fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Appends a little-endian u64.
pub fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Bounded decode cursor.
#[derive(Debug, Clone, Copy)]
pub struct Cursor<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Creates a new cursor.
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    /// Returns bytes consumed so far.
    pub const fn position(self) -> usize {
        self.pos
    }

    /// Returns true if the cursor consumed all input bytes.
    pub const fn is_finished(self) -> bool {
        self.pos == self.input.len()
    }

    /// Returns remaining bytes.
    pub fn remaining(self) -> &'a [u8] {
        &self.input[self.pos..]
    }

    /// Takes exactly `len` bytes.
    pub fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(TokenError::MalformedToken)?;
        if end > self.input.len() {
            return Err(TokenError::UnexpectedEof);
        }
        let bytes = &self.input[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    /// Reads one byte.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Reads a little-endian u16.
    pub fn u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Reads a little-endian u32.
    pub fn u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Reads a little-endian u64.
    pub fn u64(&mut self) -> Result<u64> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Reads an unsigned varint.
    pub fn varint(&mut self) -> Result<u64> {
        let (value, used) = decode_u64(self.remaining()).map_err(TokenError::from)?;
        self.pos += used;
        Ok(value)
    }

    /// Reads a length-prefixed bounded byte vector.
    pub fn bytes(&mut self, max_len: usize) -> Result<Vec<u8>> {
        let len = self.varint()?;
        let len = usize::try_from(len).map_err(|_| TokenError::ResourceExceeded)?;
        if len > max_len {
            return Err(TokenError::ResourceExceeded);
        }
        Ok(self.take(len)?.to_vec())
    }

    /// Reads a length-prefixed bounded UTF-8 string.
    pub fn string(&mut self, max_len: usize) -> Result<String> {
        let bytes = self.bytes(max_len)?;
        String::from_utf8(bytes).map_err(|_| TokenError::InvalidUtf8)
    }
}
