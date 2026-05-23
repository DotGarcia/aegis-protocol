//! Message-envelope header helpers.

use aegis_protocol_core::{Error, Result, SchemaId};

/// Length of an Aegis message nonce.
pub const ENVELOPE_NONCE_LEN: usize = 24;
/// Length of an AEAD authentication tag used by the message-envelope profile.
pub const ENVELOPE_TAG_LEN: usize = 16;
/// Fixed envelope header length before ciphertext.
pub const ENVELOPE_HEADER_LEN: usize = 56;

/// Authentication envelope metadata for brokered/offline messages.
///
/// This type does not implement cryptography. It provides deterministic
/// encoding for the metadata that cryptographic code should bind as AAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageEnvelopeHeader {
    /// Schema fingerprint bound to the ciphertext.
    pub schema_id: SchemaId,
    /// Stable message type.
    pub message_type: u32,
    /// Monotonic or unique sequence value for replay protection.
    pub sequence: u64,
    /// Length of ciphertext bytes following this header.
    pub ciphertext_len: u32,
    /// Nonce used by the selected AEAD.
    pub nonce: [u8; ENVELOPE_NONCE_LEN],
}

impl MessageEnvelopeHeader {
    /// Encodes the envelope header.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        if out.len() < ENVELOPE_HEADER_LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0..16].copy_from_slice(self.schema_id.as_bytes());
        out[16..20].copy_from_slice(&self.message_type.to_le_bytes());
        out[20..28].copy_from_slice(&self.sequence.to_le_bytes());
        out[28..32].copy_from_slice(&self.ciphertext_len.to_le_bytes());
        out[32..56].copy_from_slice(&self.nonce);
        Ok(ENVELOPE_HEADER_LEN)
    }

    /// Decodes an envelope header.
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < ENVELOPE_HEADER_LEN {
            return Err(Error::UnexpectedEof);
        }
        let mut schema = [0u8; 16];
        schema.copy_from_slice(&input[0..16]);
        let mut nonce = [0u8; ENVELOPE_NONCE_LEN];
        nonce.copy_from_slice(&input[32..56]);
        Ok(Self {
            schema_id: SchemaId::new(schema),
            message_type: u32::from_le_bytes([input[16], input[17], input[18], input[19]]),
            sequence: u64::from_le_bytes([
                input[20], input[21], input[22], input[23], input[24], input[25], input[26],
                input[27],
            ]),
            ciphertext_len: u32::from_le_bytes([input[28], input[29], input[30], input[31]]),
            nonce,
        })
    }

    /// Returns the bytes that should be included as authenticated associated data.
    pub fn aad<'a>(&self, encoded_header: &'a [u8]) -> Result<&'a [u8]> {
        if encoded_header.len() < ENVELOPE_HEADER_LEN {
            return Err(Error::UnexpectedEof);
        }
        Ok(&encoded_header[..ENVELOPE_HEADER_LEN])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_envelope_header() {
        let header = MessageEnvelopeHeader {
            schema_id: SchemaId::new([7; 16]),
            message_type: 0x2101,
            sequence: 123,
            ciphertext_len: 456,
            nonce: [9; ENVELOPE_NONCE_LEN],
        };
        let mut out = [0u8; ENVELOPE_HEADER_LEN];
        header.encode(&mut out).unwrap();
        assert_eq!(MessageEnvelopeHeader::decode(&out).unwrap(), header);
    }
}
