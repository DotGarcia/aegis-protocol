//! Control-plane frame header.

use aegis_protocol_core::{Error, ResourceBudget, Result, SchemaId, PROTOCOL_VERSION};

/// Control frame magic bytes.
pub const CONTROL_MAGIC: [u8; 4] = *b"AGS1";

/// Control frame header length.
pub const CONTROL_HEADER_LEN: usize = 64;

/// Fixed 64-byte control frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlFrameHeader {
    /// Protocol version.
    pub version: u8,
    /// Frame flags.
    pub flags: u16,
    /// Connection identifier.
    pub connection_id: u64,
    /// Stream identifier.
    pub stream_id: u32,
    /// Stable message type.
    pub message_type: u32,
    /// Schema fingerprint.
    pub schema_id: SchemaId,
    /// Monotonic frame sequence.
    pub sequence: u64,
    /// Payload length in bytes.
    pub payload_len: u32,
    /// Negotiated budget slot.
    pub budget_slot: u16,
    /// Negotiated codec id.
    pub codec: u8,
    /// Negotiated security mode.
    pub security_mode: u8,
    /// Short transcript hash binding this frame to handshake negotiation.
    pub transcript_hash: u32,
    /// Header MAC placeholder for profile-specific authentication.
    pub header_mac: u32,
}

impl ControlFrameHeader {
    /// Creates a new control header with the current protocol version.
    pub const fn new(
        flags: u16,
        connection_id: u64,
        stream_id: u32,
        message_type: u32,
        schema_id: SchemaId,
        sequence: u64,
        payload_len: u32,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            flags,
            connection_id,
            stream_id,
            message_type,
            schema_id,
            sequence,
            payload_len,
            budget_slot: 0,
            codec: 0,
            security_mode: 0,
            transcript_hash: 0,
            header_mac: 0,
        }
    }

    /// Encodes this header into `out`.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        if out.len() < CONTROL_HEADER_LEN {
            return Err(Error::BufferTooSmall);
        }

        out[0..4].copy_from_slice(&CONTROL_MAGIC);
        out[4] = self.version;
        out[5] = CONTROL_HEADER_LEN as u8;
        out[6..8].copy_from_slice(&self.flags.to_le_bytes());
        out[8..16].copy_from_slice(&self.connection_id.to_le_bytes());
        out[16..20].copy_from_slice(&self.stream_id.to_le_bytes());
        out[20..24].copy_from_slice(&self.message_type.to_le_bytes());
        out[24..40].copy_from_slice(self.schema_id.as_bytes());
        out[40..48].copy_from_slice(&self.sequence.to_le_bytes());
        out[48..52].copy_from_slice(&self.payload_len.to_le_bytes());
        out[52..54].copy_from_slice(&self.budget_slot.to_le_bytes());
        out[54] = self.codec;
        out[55] = self.security_mode;
        out[56..60].copy_from_slice(&self.transcript_hash.to_le_bytes());
        out[60..64].copy_from_slice(&self.header_mac.to_le_bytes());
        Ok(CONTROL_HEADER_LEN)
    }

    /// Decodes and validates a control frame header.
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < CONTROL_HEADER_LEN {
            return Err(Error::UnexpectedEof);
        }
        if &input[0..4] != CONTROL_MAGIC.as_ref() {
            return Err(Error::BadMagic);
        }
        if input[4] != PROTOCOL_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if input[5] as usize != CONTROL_HEADER_LEN {
            return Err(Error::MalformedFrame);
        }

        let mut schema_bytes = [0u8; 16];
        schema_bytes.copy_from_slice(&input[24..40]);

        Ok(Self {
            version: input[4],
            flags: u16::from_le_bytes([input[6], input[7]]),
            connection_id: u64::from_le_bytes([
                input[8], input[9], input[10], input[11], input[12], input[13], input[14],
                input[15],
            ]),
            stream_id: u32::from_le_bytes([input[16], input[17], input[18], input[19]]),
            message_type: u32::from_le_bytes([input[20], input[21], input[22], input[23]]),
            schema_id: SchemaId::new(schema_bytes),
            sequence: u64::from_le_bytes([
                input[40], input[41], input[42], input[43], input[44], input[45], input[46],
                input[47],
            ]),
            payload_len: u32::from_le_bytes([input[48], input[49], input[50], input[51]]),
            budget_slot: u16::from_le_bytes([input[52], input[53]]),
            codec: input[54],
            security_mode: input[55],
            transcript_hash: u32::from_le_bytes([input[56], input[57], input[58], input[59]]),
            header_mac: u32::from_le_bytes([input[60], input[61], input[62], input[63]]),
        })
    }

    /// Validates payload length against a resource budget.
    pub fn validate_payload_len(&self, budget: &ResourceBudget) -> Result<()> {
        budget.ensure_frame_size(self.payload_len as usize)
    }

    /// Decodes a control header and checks the payload length against a budget.
    pub fn decode_with_budget(input: &[u8], budget: &ResourceBudget) -> Result<Self> {
        let header = Self::decode(input)?;
        header.validate_payload_len(budget)?;
        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_control_header() {
        let mut header = ControlFrameHeader::new(7, 42, 9, 0x2101, SchemaId::new([1; 16]), 99, 128);
        header.budget_slot = 2;
        header.codec = 0;
        header.security_mode = 0;
        header.transcript_hash = 0xaaaa_bbbb;
        header.header_mac = 0xcccc_dddd;
        let mut out = [0u8; CONTROL_HEADER_LEN];
        header.encode(&mut out).unwrap();
        assert_eq!(ControlFrameHeader::decode(&out).unwrap(), header);
    }
}
