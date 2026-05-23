//! Codec identifiers and compression policy helpers.

use core::convert::TryFrom;

use crate::{Error, Result};

/// Negotiated compression or payload codec.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// No compression.
    None = 0,
    /// LZ4-style low-latency compression.
    Lz4 = 1,
    /// Zstandard compression.
    Zstd = 2,
    /// Zstandard with a negotiated dictionary.
    ZstdDict = 3,
}

impl Codec {
    /// Returns true if this codec compresses payload bytes.
    pub const fn is_compressed(self) -> bool {
        !matches!(self, Self::None)
    }
}

impl TryFrom<u8> for Codec {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Lz4),
            2 => Ok(Self::Zstd),
            3 => Ok(Self::ZstdDict),
            _ => Err(Error::UnknownCodec),
        }
    }
}

/// Contextual policy for compression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionPolicy {
    /// Codec selected for this payload class.
    pub codec: Codec,
    /// Maximum allowed decompression ratio.
    pub max_ratio: usize,
    /// Maximum decoded output size.
    pub max_output_size: usize,
    /// Whether this message carries secrets.
    pub secrets_present: bool,
    /// Whether user-controlled input is compressed in the same context.
    pub user_controlled_input: bool,
}

impl CompressionPolicy {
    /// Policy for uncompressed traffic.
    pub const fn none(max_output_size: usize) -> Self {
        Self {
            codec: Codec::None,
            max_ratio: 1,
            max_output_size,
            secrets_present: false,
            user_controlled_input: false,
        }
    }

    /// Returns true when compression is allowed by side-channel policy.
    pub const fn allows_compression(self) -> bool {
        !(self.codec.is_compressed() && self.secrets_present && self.user_controlled_input)
    }

    /// Validates compression policy and output bounds.
    pub fn validate(self, compressed_len: usize, decoded_len: usize) -> Result<()> {
        if !self.allows_compression() {
            return Err(Error::PolicyViolation);
        }
        if decoded_len > self.max_output_size {
            return Err(Error::ResourceExceeded);
        }
        if self.codec.is_compressed() {
            if compressed_len == 0 {
                return Err(Error::MalformedFrame);
            }
            if decoded_len > compressed_len.saturating_mul(self.max_ratio) {
                return Err(Error::ResourceExceeded);
            }
        }
        Ok(())
    }
}
