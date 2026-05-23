//! Minimal unsigned varint and signed zig-zag helpers.

use crate::{Error, Result};

/// Maximum number of bytes needed for a u64 varint.
pub const MAX_U64_VARINT_LEN: usize = 10;

/// Returns the encoded length of a `u64` varint.
pub const fn encoded_len_u64(mut value: u64) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

/// Encodes `value` into `out`, returning bytes written.
pub fn encode_u64(mut value: u64, out: &mut [u8]) -> Result<usize> {
    let needed = encoded_len_u64(value);
    if out.len() < needed {
        return Err(Error::BufferTooSmall);
    }

    let mut pos = 0;
    while value >= 0x80 {
        out[pos] = ((value as u8) & 0x7f) | 0x80;
        value >>= 7;
        pos += 1;
    }
    out[pos] = value as u8;
    Ok(pos + 1)
}

/// Decodes a `u64` varint from `input`, returning value and bytes consumed.
pub fn decode_u64(input: &[u8]) -> Result<(u64, usize)> {
    let mut result = 0u64;

    for (i, byte) in input.iter().copied().take(MAX_U64_VARINT_LEN).enumerate() {
        let part = (byte & 0x7f) as u64;
        if i == 9 && part > 1 {
            return Err(Error::VarintOverflow);
        }
        result |= part << (i * 7);
        if byte & 0x80 == 0 {
            return Ok((result, i + 1));
        }
    }

    if input.len() >= MAX_U64_VARINT_LEN {
        Err(Error::VarintOverflow)
    } else {
        Err(Error::UnexpectedEof)
    }
}

/// Zig-zag encodes a signed integer for compact varint representation.
pub const fn zigzag_encode_i64(value: i64) -> u64 {
    ((value as u64) << 1) ^ ((value >> 63) as u64)
}

/// Decodes a zig-zag encoded signed integer.
pub const fn zigzag_decode_i64(value: u64) -> i64 {
    ((value >> 1) as i64) ^ (-((value & 1) as i64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_varints() {
        let cases = [0, 1, 2, 127, 128, 255, 16_384, u32::MAX as u64, u64::MAX];
        for case in cases {
            let mut out = [0u8; MAX_U64_VARINT_LEN];
            let len = encode_u64(case, &mut out).unwrap();
            let (decoded, used) = decode_u64(&out[..len]).unwrap();
            assert_eq!(decoded, case);
            assert_eq!(used, len);
        }
    }

    #[test]
    fn round_trips_zigzag() {
        let cases = [
            0,
            -1,
            1,
            -2,
            2,
            i32::MIN as i64,
            i32::MAX as i64,
            i64::MIN + 1,
            i64::MAX,
        ];
        for case in cases {
            assert_eq!(zigzag_decode_i64(zigzag_encode_i64(case)), case);
        }
    }
}
