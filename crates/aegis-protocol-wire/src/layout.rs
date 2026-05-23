//! Payload section splitting and variable field validation.

use aegis_protocol_core::{BytesView, Error, Result, StrView};

/// Size of one variable-index entry: `u32 offset` + `u32 length`.
pub const VARIABLE_INDEX_ENTRY_LEN: usize = 8;

/// Payload section lengths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutSpec {
    /// Required fixed region length.
    pub required_fixed_len: usize,
    /// Optional presence bitmap length.
    pub optional_bitmap_len: usize,
    /// Optional fixed region length.
    pub optional_fixed_len: usize,
    /// Variable index length.
    pub variable_index_len: usize,
}

impl LayoutSpec {
    /// Returns the prefix length before the variable region.
    pub fn prefix_len(self) -> Result<usize> {
        self.required_fixed_len
            .checked_add(self.optional_bitmap_len)
            .and_then(|n| n.checked_add(self.optional_fixed_len))
            .and_then(|n| n.checked_add(self.variable_index_len))
            .ok_or(Error::ResourceExceeded)
    }

    /// Returns the number of variable-index entries.
    pub fn variable_entry_count(self) -> Result<usize> {
        if self.variable_index_len % VARIABLE_INDEX_ENTRY_LEN != 0 {
            return Err(Error::MalformedFrame);
        }
        Ok(self.variable_index_len / VARIABLE_INDEX_ENTRY_LEN)
    }
}

/// Borrowed sections of an Aegis payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadSections<'a> {
    /// Required fixed region.
    pub required_fixed: &'a [u8],
    /// Optional field presence bitmap.
    pub optional_bitmap: &'a [u8],
    /// Optional fixed region.
    pub optional_fixed: &'a [u8],
    /// Variable index region.
    pub variable_index: &'a [u8],
    /// Variable data region.
    pub variable_region: &'a [u8],
}

/// One variable-index entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VariableIndexEntry {
    /// Offset inside the variable region.
    pub offset: u32,
    /// Length inside the variable region.
    pub length: u32,
}

/// Splits a validated payload according to `spec`.
pub fn split_payload<'a>(payload: &'a [u8], spec: LayoutSpec) -> Result<PayloadSections<'a>> {
    let prefix_len = spec.prefix_len()?;
    spec.variable_entry_count()?;
    if payload.len() < prefix_len {
        return Err(Error::UnexpectedEof);
    }

    let mut pos = 0;
    let required_fixed = &payload[pos..pos + spec.required_fixed_len];
    pos += spec.required_fixed_len;
    let optional_bitmap = &payload[pos..pos + spec.optional_bitmap_len];
    pos += spec.optional_bitmap_len;
    let optional_fixed = &payload[pos..pos + spec.optional_fixed_len];
    pos += spec.optional_fixed_len;
    let variable_index = &payload[pos..pos + spec.variable_index_len];
    pos += spec.variable_index_len;
    let variable_region = &payload[pos..];

    Ok(PayloadSections {
        required_fixed,
        optional_bitmap,
        optional_fixed,
        variable_index,
        variable_region,
    })
}

/// Returns whether an optional field ordinal is present in a bitmap.
pub fn optional_field_present(bitmap: &[u8], ordinal: usize) -> Result<bool> {
    let byte_index = ordinal / 8;
    let bit_index = ordinal % 8;
    let Some(byte) = bitmap.get(byte_index) else {
        return Err(Error::UnexpectedEof);
    };
    Ok((byte & (1u8 << bit_index)) != 0)
}

/// Reads a variable-index entry by ordinal.
pub fn read_variable_index_entry(index: &[u8], ordinal: usize) -> Result<VariableIndexEntry> {
    let start = ordinal
        .checked_mul(VARIABLE_INDEX_ENTRY_LEN)
        .ok_or(Error::ResourceExceeded)?;
    let end = start
        .checked_add(VARIABLE_INDEX_ENTRY_LEN)
        .ok_or(Error::ResourceExceeded)?;
    if end > index.len() {
        return Err(Error::UnexpectedEof);
    }

    Ok(VariableIndexEntry {
        offset: u32::from_le_bytes([
            index[start],
            index[start + 1],
            index[start + 2],
            index[start + 3],
        ]),
        length: u32::from_le_bytes([
            index[start + 4],
            index[start + 5],
            index[start + 6],
            index[start + 7],
        ]),
    })
}

/// Validates all variable-index entries against the variable region.
pub fn validate_variable_index_table(
    sections: &PayloadSections<'_>,
    max_entry_len: usize,
) -> Result<()> {
    if sections.variable_index.len() % VARIABLE_INDEX_ENTRY_LEN != 0 {
        return Err(Error::MalformedFrame);
    }
    let entries = sections.variable_index.len() / VARIABLE_INDEX_ENTRY_LEN;
    for ordinal in 0..entries {
        let entry = read_variable_index_entry(sections.variable_index, ordinal)?;
        let start = entry.offset as usize;
        let len = entry.length as usize;
        if len > max_entry_len {
            return Err(Error::ResourceExceeded);
        }
        let end = start.checked_add(len).ok_or(Error::OffsetOutOfRange)?;
        if end > sections.variable_region.len() {
            return Err(Error::OffsetOutOfRange);
        }
    }
    Ok(())
}

/// Validates and returns a zero-copy view of a variable bytes field.
pub fn variable_view<'a>(
    sections: &PayloadSections<'a>,
    entry: VariableIndexEntry,
    max_len: usize,
) -> Result<BytesView<'a>> {
    let start = entry.offset as usize;
    let len = entry.length as usize;
    if len > max_len {
        return Err(Error::ResourceExceeded);
    }
    let end = start.checked_add(len).ok_or(Error::OffsetOutOfRange)?;
    if end > sections.variable_region.len() {
        return Err(Error::OffsetOutOfRange);
    }
    BytesView::try_from_bytes_with_limit(&sections.variable_region[start..end], max_len)
}

/// Validates and returns a zero-copy view of a variable string field.
pub fn variable_str_view<'a>(
    sections: &PayloadSections<'a>,
    entry: VariableIndexEntry,
    max_len: usize,
    no_control_chars: bool,
) -> Result<StrView<'a>> {
    let bytes = variable_view(sections, entry, max_len)?;
    StrView::try_from_bytes_with_policy(bytes.as_bytes(), max_len, no_control_chars)
}

/// Reads a little-endian `u16` from a fixed region.
pub fn read_u16_le(region: &[u8], offset: usize) -> Result<u16> {
    let end = offset.checked_add(2).ok_or(Error::ResourceExceeded)?;
    if end > region.len() {
        return Err(Error::UnexpectedEof);
    }
    Ok(u16::from_le_bytes([region[offset], region[offset + 1]]))
}

/// Reads a little-endian `u32` from a fixed region.
pub fn read_u32_le(region: &[u8], offset: usize) -> Result<u32> {
    let end = offset.checked_add(4).ok_or(Error::ResourceExceeded)?;
    if end > region.len() {
        return Err(Error::UnexpectedEof);
    }
    Ok(u32::from_le_bytes([
        region[offset],
        region[offset + 1],
        region[offset + 2],
        region[offset + 3],
    ]))
}

/// Reads a little-endian `u64` from a fixed region.
pub fn read_u64_le(region: &[u8], offset: usize) -> Result<u64> {
    let end = offset.checked_add(8).ok_or(Error::ResourceExceeded)?;
    if end > region.len() {
        return Err(Error::UnexpectedEof);
    }
    Ok(u64::from_le_bytes([
        region[offset],
        region[offset + 1],
        region[offset + 2],
        region[offset + 3],
        region[offset + 4],
        region[offset + 5],
        region[offset + 6],
        region[offset + 7],
    ]))
}

/// Reads a little-endian `i64` from a fixed region.
pub fn read_i64_le(region: &[u8], offset: usize) -> Result<i64> {
    read_u64_le(region, offset).map(|value| value as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_variable_view() {
        let payload = [
            1, 2, 3, 4, // required fixed
            1, // bitmap
            9, 9, // optional fixed
            0, 0, 0, 0, 3, 0, 0, 0, // index: offset 0, length 3
            b'a', b'b', b'c',
        ];
        let sections = split_payload(
            &payload,
            LayoutSpec {
                required_fixed_len: 4,
                optional_bitmap_len: 1,
                optional_fixed_len: 2,
                variable_index_len: 8,
            },
        )
        .unwrap();
        let entry = read_variable_index_entry(sections.variable_index, 0).unwrap();
        let view = variable_view(&sections, entry, 3).unwrap();
        assert_eq!(view.as_bytes(), b"abc");
        assert!(optional_field_present(sections.optional_bitmap, 0).unwrap());
        assert_eq!(
            read_u32_le(sections.required_fixed, 0).unwrap(),
            0x0403_0201
        );
    }

    #[test]
    fn validates_string_policy() {
        let payload = [0, 0, 0, 0, 5, 0, 0, 0, b'h', b'e', b'l', b'l', b'o'];
        let sections = split_payload(
            &payload,
            LayoutSpec {
                required_fixed_len: 0,
                optional_bitmap_len: 0,
                optional_fixed_len: 0,
                variable_index_len: 8,
            },
        )
        .unwrap();
        let entry = read_variable_index_entry(sections.variable_index, 0).unwrap();
        let view = variable_str_view(&sections, entry, 5, true).unwrap();
        assert_eq!(view.as_str(), "hello");
    }
}
