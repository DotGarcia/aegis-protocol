//! Compact hot-path frame header.

use aegis_protocol_core::{
    varint, BudgetSlot, CapabilitySlot, Error, ResourceBudget, Result, StreamSlot, TypeSlot,
};

/// Conservative maximum encoded hot-frame header length.
pub const MAX_HOT_HEADER_LEN: usize = 1 + (6 * varint::MAX_U64_VARINT_LEN);

/// Compact hot-path data frame header.
///
/// The header uses varints because, after negotiation, most slots are small.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HotFrameHeader {
    /// Frame flags.
    pub flags: u8,
    /// Negotiated stream slot.
    pub stream_slot: StreamSlot,
    /// Negotiated message type slot.
    pub type_slot: TypeSlot,
    /// Negotiated capability slot.
    pub capability_slot: CapabilitySlot,
    /// Negotiated resource budget slot.
    pub budget_slot: BudgetSlot,
    /// Sequence delta from the previous accepted frame on this stream.
    pub seq_delta: u64,
    /// Payload length in bytes.
    pub payload_len: u64,
}

impl HotFrameHeader {
    /// Returns the exact encoded length of this compact header.
    pub const fn encoded_len(&self) -> usize {
        1 + varint::encoded_len_u64(self.stream_slot.get() as u64)
            + varint::encoded_len_u64(self.type_slot.get() as u64)
            + varint::encoded_len_u64(self.capability_slot.get() as u64)
            + varint::encoded_len_u64(self.budget_slot.get() as u64)
            + varint::encoded_len_u64(self.seq_delta)
            + varint::encoded_len_u64(self.payload_len)
    }

    /// Encodes this compact header into `out`, returning bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        if out.len() < self.encoded_len() {
            return Err(Error::BufferTooSmall);
        }

        let mut pos = 0;
        out[pos] = self.flags;
        pos += 1;

        pos += varint::encode_u64(self.stream_slot.get() as u64, &mut out[pos..])?;
        pos += varint::encode_u64(self.type_slot.get() as u64, &mut out[pos..])?;
        pos += varint::encode_u64(self.capability_slot.get() as u64, &mut out[pos..])?;
        pos += varint::encode_u64(self.budget_slot.get() as u64, &mut out[pos..])?;
        pos += varint::encode_u64(self.seq_delta, &mut out[pos..])?;
        pos += varint::encode_u64(self.payload_len, &mut out[pos..])?;
        Ok(pos)
    }

    /// Decodes a compact header from `input`, returning header and bytes used.
    pub fn decode(input: &[u8]) -> Result<(Self, usize)> {
        if input.is_empty() {
            return Err(Error::UnexpectedEof);
        }

        let mut pos = 0;
        let flags = input[pos];
        pos += 1;

        let (stream_slot, used) = varint::decode_u64(&input[pos..])?;
        pos += used;
        let (type_slot, used) = varint::decode_u64(&input[pos..])?;
        pos += used;
        let (capability_slot, used) = varint::decode_u64(&input[pos..])?;
        pos += used;
        let (budget_slot, used) = varint::decode_u64(&input[pos..])?;
        pos += used;
        let (seq_delta, used) = varint::decode_u64(&input[pos..])?;
        pos += used;
        let (payload_len, used) = varint::decode_u64(&input[pos..])?;
        pos += used;

        if stream_slot > u32::MAX as u64
            || type_slot > u16::MAX as u64
            || capability_slot > u16::MAX as u64
            || budget_slot > u16::MAX as u64
        {
            return Err(Error::MalformedFrame);
        }

        Ok((
            Self {
                flags,
                stream_slot: StreamSlot::new(stream_slot as u32),
                type_slot: TypeSlot::new(type_slot as u16),
                capability_slot: CapabilitySlot::new(capability_slot as u16),
                budget_slot: BudgetSlot::new(budget_slot as u16),
                seq_delta,
                payload_len,
            },
            pos,
        ))
    }

    /// Validates payload length against a resource budget.
    pub fn validate_payload_len(&self, budget: &ResourceBudget) -> Result<()> {
        if self.payload_len > usize::MAX as u64 {
            return Err(Error::ResourceExceeded);
        }
        budget.ensure_frame_size(self.payload_len as usize)
    }

    /// Decodes a compact header and checks the payload length against a budget.
    pub fn decode_with_budget(input: &[u8], budget: &ResourceBudget) -> Result<(Self, usize)> {
        let (header, used) = Self::decode(input)?;
        header.validate_payload_len(budget)?;
        Ok((header, used))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_hot_header() {
        let header = HotFrameHeader {
            flags: 1,
            stream_slot: StreamSlot::new(2),
            type_slot: TypeSlot::new(3),
            capability_slot: CapabilitySlot::new(4),
            budget_slot: BudgetSlot::new(5),
            seq_delta: 6,
            payload_len: 128,
        };
        let mut out = [0u8; 64];
        let len = header.encode(&mut out).unwrap();
        assert_eq!(len, header.encoded_len());
        let (decoded, used) = HotFrameHeader::decode(&out[..len]).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(used, len);
    }

    #[test]
    fn rejects_over_budget_payload() {
        let header = HotFrameHeader {
            flags: 0,
            stream_slot: StreamSlot::new(1),
            type_slot: TypeSlot::new(1),
            capability_slot: CapabilitySlot::new(1),
            budget_slot: BudgetSlot::new(1),
            seq_delta: 1,
            payload_len: 1024 * 1024,
        };
        assert_eq!(
            header.validate_payload_len(&ResourceBudget::tiny()),
            Err(Error::ResourceExceeded)
        );
    }
}
