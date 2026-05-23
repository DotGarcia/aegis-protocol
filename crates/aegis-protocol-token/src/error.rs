//! Token-specific error types.

use core::fmt;

/// Convenient result alias for token operations.
pub type Result<T> = core::result::Result<T, TokenError>;

/// Errors produced by Aegis Capability Token encoding, decoding and validation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TokenError {
    /// The token uses invalid magic bytes or an invalid compact prefix.
    BadMagic,
    /// The token version is not supported.
    UnsupportedVersion,
    /// The token is malformed or structurally invalid.
    MalformedToken,
    /// An algorithm identifier is not recognized.
    UnknownAlgorithm,
    /// A token profile identifier is not recognized.
    UnknownProfile,
    /// A token flag or capability flag violates policy.
    PolicyViolation,
    /// A supplied buffer was too small for encoding.
    BufferTooSmall,
    /// Input ended before a full token component could be decoded.
    UnexpectedEof,
    /// A varint did not terminate within the maximum encoded length.
    VarintOverflow,
    /// A token string used invalid base64url syntax.
    InvalidBase64Url,
    /// UTF-8 validation failed.
    InvalidUtf8,
    /// A decoded token exceeded a configured resource limit.
    ResourceExceeded,
    /// Signature verification failed.
    SignatureInvalid,
    /// The token is expired.
    Expired,
    /// The token is not valid yet.
    NotYetValid,
    /// The token audience did not match the required audience.
    AudienceMismatch,
    /// The token schema did not match the required schema.
    SchemaMismatch,
    /// The token does not contain the required capability.
    CapabilityDenied,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::BadMagic => "bad token magic or compact prefix",
            Self::UnsupportedVersion => "unsupported token version",
            Self::MalformedToken => "malformed token",
            Self::UnknownAlgorithm => "unknown token algorithm",
            Self::UnknownProfile => "unknown token profile",
            Self::PolicyViolation => "token policy violation",
            Self::BufferTooSmall => "buffer too small",
            Self::UnexpectedEof => "unexpected end of token input",
            Self::VarintOverflow => "token varint overflow",
            Self::InvalidBase64Url => "invalid base64url token segment",
            Self::InvalidUtf8 => "invalid UTF-8 in token",
            Self::ResourceExceeded => "token resource limit exceeded",
            Self::SignatureInvalid => "token signature invalid",
            Self::Expired => "token expired",
            Self::NotYetValid => "token not valid yet",
            Self::AudienceMismatch => "token audience mismatch",
            Self::SchemaMismatch => "token schema mismatch",
            Self::CapabilityDenied => "token capability denied",
        };
        f.write_str(message)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TokenError {}

impl From<aegis_protocol_core::Error> for TokenError {
    fn from(value: aegis_protocol_core::Error) -> Self {
        use aegis_protocol_core::Error;
        match value {
            Error::UnsupportedVersion => Self::UnsupportedVersion,
            Error::ResourceExceeded => Self::ResourceExceeded,
            Error::UnexpectedEof => Self::UnexpectedEof,
            Error::VarintOverflow => Self::VarintOverflow,
            Error::InvalidUtf8 => Self::InvalidUtf8,
            Error::BufferTooSmall => Self::BufferTooSmall,
            Error::SchemaMismatch => Self::SchemaMismatch,
            Error::CapabilityDenied => Self::CapabilityDenied,
            Error::PolicyViolation => Self::PolicyViolation,
            _ => Self::MalformedToken,
        }
    }
}
