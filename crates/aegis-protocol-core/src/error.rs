//! Error and result types.

use core::fmt;

/// Convenient result alias for Aegis operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors produced by Aegis validation, framing and decoding primitives.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A frame used invalid magic bytes.
    BadMagic,
    /// A frame was malformed or structurally invalid.
    MalformedFrame,
    /// A payload exceeded a configured resource budget.
    ResourceExceeded,
    /// The protocol version is not supported.
    UnsupportedVersion,
    /// The frame kind byte is not recognized.
    UnknownFrameKind,
    /// The codec byte is not recognized.
    UnknownCodec,
    /// A schema identifier did not match the expected schema.
    SchemaMismatch,
    /// The capability attached to an operation is not allowed.
    CapabilityDenied,
    /// The operation is not allowed in the current session state.
    StateDenied,
    /// An idempotency key was required but missing or invalid.
    IdempotencyRequired,
    /// A replayed or stale sequence was detected.
    ReplayDetected,
    /// A security or compression policy was violated.
    PolicyViolation,
    /// A varint did not terminate within the maximum encoded length.
    VarintOverflow,
    /// Input ended before a full value could be decoded.
    UnexpectedEof,
    /// UTF-8 validation failed.
    InvalidUtf8,
    /// A variable-length field pointed outside the variable region.
    OffsetOutOfRange,
    /// A supplied buffer was too small for encoding.
    BufferTooSmall,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::BadMagic => "bad frame magic",
            Self::MalformedFrame => "malformed frame",
            Self::ResourceExceeded => "resource budget exceeded",
            Self::UnsupportedVersion => "unsupported protocol version",
            Self::UnknownFrameKind => "unknown frame kind",
            Self::UnknownCodec => "unknown codec",
            Self::SchemaMismatch => "schema mismatch",
            Self::CapabilityDenied => "capability denied",
            Self::StateDenied => "state denied",
            Self::IdempotencyRequired => "idempotency key required",
            Self::ReplayDetected => "replay detected",
            Self::PolicyViolation => "policy violation",
            Self::VarintOverflow => "varint overflow",
            Self::UnexpectedEof => "unexpected end of input",
            Self::InvalidUtf8 => "invalid UTF-8",
            Self::OffsetOutOfRange => "offset out of range",
            Self::BufferTooSmall => "buffer too small",
        };
        f.write_str(message)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
