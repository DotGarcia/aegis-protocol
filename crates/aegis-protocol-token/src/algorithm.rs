//! Token algorithm and profile identifiers.

use core::convert::TryFrom;

use crate::{Result, TokenError};

/// Signing algorithm identifier for an Aegis Capability Token.
///
/// The crate intentionally does not implement these algorithms. Applications
/// provide signing and verification through the `TokenSigner` and
/// `TokenVerifier` traits.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenAlgorithm {
    /// Unsecured token, only allowed when validation policy explicitly permits it.
    Unsecured = 0,
    /// Ed25519 signature.
    Ed25519 = 1,
    /// HMAC using SHA-256.
    HmacSha256 = 2,
    /// ECDSA P-256 using SHA-256.
    EcdsaP256Sha256 = 3,
    /// A post-quantum or hybrid signature selected by deployment policy.
    DeploymentDefined = 255,
}

impl TokenAlgorithm {
    /// Returns true when this algorithm represents a cryptographic signature.
    pub const fn is_signed(self) -> bool {
        !matches!(self, Self::Unsecured)
    }
}

impl TryFrom<u8> for TokenAlgorithm {
    type Error = TokenError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Unsecured),
            1 => Ok(Self::Ed25519),
            2 => Ok(Self::HmacSha256),
            3 => Ok(Self::EcdsaP256Sha256),
            255 => Ok(Self::DeploymentDefined),
            _ => Err(TokenError::UnknownAlgorithm),
        }
    }
}

/// High-level ACT token profile.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenProfile {
    /// Short-lived access token carrying capabilities.
    Access = 1,
    /// Delegation token that can mint narrower tokens when policy allows it.
    Delegation = 2,
    /// Refresh token, normally stored only by trusted clients.
    Refresh = 3,
    /// Session token bound to an Aegis handshake transcript.
    Session = 4,
}

impl TryFrom<u8> for TokenProfile {
    type Error = TokenError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Access),
            2 => Ok(Self::Delegation),
            3 => Ok(Self::Refresh),
            4 => Ok(Self::Session),
            _ => Err(TokenError::UnknownProfile),
        }
    }
}
