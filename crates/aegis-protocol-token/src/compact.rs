//! Base64url compact-token helpers.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{Result, TokenError};

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encodes bytes using unpadded base64url.
pub fn base64url_encode(input: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | input[i + 2] as u32;
        out.push(B64URL[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64URL[((n >> 12) & 0x3f) as usize] as char);
        out.push(B64URL[((n >> 6) & 0x3f) as usize] as char);
        out.push(B64URL[(n & 0x3f) as usize] as char);
        i += 3;
    }

    match input.len() - i {
        1 => {
            let n = (input[i] as u32) << 16;
            out.push(B64URL[((n >> 18) & 0x3f) as usize] as char);
            out.push(B64URL[((n >> 12) & 0x3f) as usize] as char);
        }
        2 => {
            let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
            out.push(B64URL[((n >> 18) & 0x3f) as usize] as char);
            out.push(B64URL[((n >> 12) & 0x3f) as usize] as char);
            out.push(B64URL[((n >> 6) & 0x3f) as usize] as char);
        }
        _ => {}
    }

    out
}

/// Decodes unpadded base64url bytes.
pub fn base64url_decode(input: &str) -> Result<Vec<u8>> {
    if input.as_bytes().contains(&b'=') || input.len() % 4 == 1 {
        return Err(TokenError::InvalidBase64Url);
    }

    let mut out = Vec::new();
    let mut chunk = [0u8; 4];
    let mut chunk_len = 0usize;

    for byte in input.bytes() {
        chunk[chunk_len] = decode_value(byte)?;
        chunk_len += 1;
        if chunk_len == 4 {
            push_decoded_chunk(&mut out, chunk, 4);
            chunk_len = 0;
        }
    }

    if chunk_len > 0 {
        push_decoded_chunk(&mut out, chunk, chunk_len);
    }

    Ok(out)
}

fn push_decoded_chunk(out: &mut Vec<u8>, chunk: [u8; 4], len: usize) {
    let n = ((chunk[0] as u32) << 18)
        | ((chunk[1] as u32) << 12)
        | ((chunk[2] as u32) << 6)
        | chunk[3] as u32;

    if len >= 2 {
        out.push(((n >> 16) & 0xff) as u8);
    }
    if len >= 3 {
        out.push(((n >> 8) & 0xff) as u8);
    }
    if len >= 4 {
        out.push((n & 0xff) as u8);
    }
}

fn decode_value(byte: u8) -> Result<u8> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err(TokenError::InvalidBase64Url),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_round_trips() {
        let cases: &[&[u8]] = &[b"", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"];
        for case in cases {
            let encoded = base64url_encode(case);
            let decoded = base64url_decode(&encoded).unwrap();
            assert_eq!(decoded.as_slice(), *case);
        }
    }
}
