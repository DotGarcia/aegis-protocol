//! Aegis Capability Token container and signing helpers.

use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryFrom;

use crate::claims::{AegisClaims, TokenHeader, ValidationContext};
use crate::codec::{push_varint, Cursor, MAX_TOKEN_BYTES};
use crate::compact::{base64url_decode, base64url_encode};
use crate::{Result, TokenAlgorithm, TokenError};

/// Binary token magic bytes.
pub const ACT_MAGIC: [u8; 4] = *b"ACT1";
/// Compact token prefix.
pub const ACT_COMPACT_PREFIX: &str = "act1";
/// ACT format version.
pub const ACT_VERSION: u8 = 1;
/// Domain separation string used for token signatures.
pub const ACT_SIGNING_DOMAIN: &[u8] = b"Aegis-ACT-v1\0";

/// Signs ACT signing input.
///
/// Implement this trait using an audited crypto library. This crate does not
/// implement signing algorithms itself.
pub trait TokenSigner {
    /// Algorithm used by this signer.
    fn algorithm(&self) -> TokenAlgorithm;

    /// Key identifier that verifiers use to select the verification key.
    fn key_id(&self) -> &[u8];

    /// Signs `signing_input` and returns the raw signature bytes.
    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>>;
}

/// Verifies ACT signatures.
pub trait TokenVerifier {
    /// Verifies raw `signature` over `signing_input` using the selected algorithm and key id.
    fn verify(
        &self,
        algorithm: TokenAlgorithm,
        key_id: &[u8],
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<()>;
}

/// Parsed Aegis Capability Token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AegisToken {
    /// Protected token header.
    pub header: TokenHeader,
    /// Token claims.
    pub claims: AegisClaims,
    /// Raw signature bytes.
    pub signature: Vec<u8>,
}

impl AegisToken {
    /// Creates an unsigned token object. Use only for tests or after separately assigning a signature.
    pub fn new(header: TokenHeader, claims: AegisClaims, signature: Vec<u8>) -> Self {
        Self {
            header,
            claims,
            signature,
        }
    }

    /// Creates and signs a token.
    pub fn sign(
        mut header: TokenHeader,
        claims: AegisClaims,
        signer: &impl TokenSigner,
    ) -> Result<Self> {
        header.algorithm = signer.algorithm();
        header.key_id.clear();
        header.key_id.extend_from_slice(signer.key_id());
        let signing_input = signing_input_for_parts(&header.encode(), &claims.encode());
        let signature = signer.sign(&signing_input)?;
        Ok(Self {
            header,
            claims,
            signature,
        })
    }

    /// Returns the deterministic signing input for this token.
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input_for_parts(&self.header.encode(), &self.claims.encode())
    }

    /// Verifies signature and validates claims.
    pub fn verify_and_validate(
        &self,
        verifier: &impl TokenVerifier,
        ctx: &ValidationContext<'_>,
    ) -> Result<()> {
        if self.header.algorithm == TokenAlgorithm::Unsecured && !ctx.allow_unsecured {
            return Err(TokenError::PolicyViolation);
        }
        if self.header.algorithm.is_signed() {
            let signing_input = self.signing_input();
            verifier.verify(
                self.header.algorithm,
                &self.header.key_id,
                &signing_input,
                &self.signature,
            )?;
        }
        self.claims.validate(ctx)
    }

    /// Encodes this token as a binary ACT container.
    pub fn encode_binary(&self) -> Vec<u8> {
        let header = self.header.encode();
        let claims = self.claims.encode();
        let mut out = Vec::new();
        out.extend_from_slice(&ACT_MAGIC);
        out.push(ACT_VERSION);
        push_varint(&mut out, header.len() as u64);
        push_varint(&mut out, claims.len() as u64);
        push_varint(&mut out, self.signature.len() as u64);
        out.extend_from_slice(&header);
        out.extend_from_slice(&claims);
        out.extend_from_slice(&self.signature);
        out
    }

    /// Decodes a binary ACT container.
    pub fn decode_binary(input: &[u8]) -> Result<Self> {
        if input.len() > MAX_TOKEN_BYTES {
            return Err(TokenError::ResourceExceeded);
        }
        let mut cursor = Cursor::new(input);
        if cursor.take(4)? != &ACT_MAGIC[..] {
            return Err(TokenError::BadMagic);
        }
        let version = cursor.u8()?;
        if version != ACT_VERSION {
            return Err(TokenError::UnsupportedVersion);
        }
        let header_len =
            usize::try_from(cursor.varint()?).map_err(|_| TokenError::ResourceExceeded)?;
        let claims_len =
            usize::try_from(cursor.varint()?).map_err(|_| TokenError::ResourceExceeded)?;
        let signature_len =
            usize::try_from(cursor.varint()?).map_err(|_| TokenError::ResourceExceeded)?;
        let total = header_len
            .checked_add(claims_len)
            .and_then(|value| value.checked_add(signature_len))
            .ok_or(TokenError::ResourceExceeded)?;
        if total > MAX_TOKEN_BYTES {
            return Err(TokenError::ResourceExceeded);
        }
        let header = TokenHeader::decode(cursor.take(header_len)?)?;
        let claims = AegisClaims::decode(cursor.take(claims_len)?)?;
        let signature = cursor.take(signature_len)?.to_vec();
        if !cursor.is_finished() {
            return Err(TokenError::MalformedToken);
        }
        Ok(Self {
            header,
            claims,
            signature,
        })
    }

    /// Encodes this token as a compact text representation.
    ///
    /// Format: `act1.<b64url(header)>.<b64url(claims)>.<b64url(signature)>`.
    pub fn encode_compact(&self) -> String {
        let mut out = String::new();
        out.push_str(ACT_COMPACT_PREFIX);
        out.push('.');
        out.push_str(&base64url_encode(&self.header.encode()));
        out.push('.');
        out.push_str(&base64url_encode(&self.claims.encode()));
        out.push('.');
        out.push_str(&base64url_encode(&self.signature));
        out
    }

    /// Decodes a compact ACT string.
    pub fn decode_compact(input: &str) -> Result<Self> {
        let mut parts = input.split('.');
        let prefix = parts.next().ok_or(TokenError::MalformedToken)?;
        if prefix != ACT_COMPACT_PREFIX {
            return Err(TokenError::BadMagic);
        }
        let header_part = parts.next().ok_or(TokenError::MalformedToken)?;
        let claims_part = parts.next().ok_or(TokenError::MalformedToken)?;
        let signature_part = parts.next().ok_or(TokenError::MalformedToken)?;
        if parts.next().is_some() {
            return Err(TokenError::MalformedToken);
        }
        let header_bytes = base64url_decode(header_part)?;
        let claims_bytes = base64url_decode(claims_part)?;
        let signature = base64url_decode(signature_part)?;
        if header_bytes.len() + claims_bytes.len() + signature.len() > MAX_TOKEN_BYTES {
            return Err(TokenError::ResourceExceeded);
        }
        Ok(Self {
            header: TokenHeader::decode(&header_bytes)?,
            claims: AegisClaims::decode(&claims_bytes)?,
            signature,
        })
    }
}

/// Builds the canonical token signing input for already-encoded header and claims.
pub fn signing_input_for_parts(header: &[u8], claims: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(ACT_SIGNING_DOMAIN);
    push_varint(&mut out, header.len() as u64);
    out.extend_from_slice(header);
    push_varint(&mut out, claims.len() as u64);
    out.extend_from_slice(claims);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CapabilityClaim, TokenProfile};
    use aegis_protocol_core::{MessageType, SchemaId};

    struct EchoSigner;

    impl TokenSigner for EchoSigner {
        fn algorithm(&self) -> TokenAlgorithm {
            TokenAlgorithm::DeploymentDefined
        }

        fn key_id(&self) -> &[u8] {
            b"test-key"
        }

        fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>> {
            Ok(signing_input[..8.min(signing_input.len())].to_vec())
        }
    }

    struct EchoVerifier;

    impl TokenVerifier for EchoVerifier {
        fn verify(
            &self,
            _algorithm: TokenAlgorithm,
            _key_id: &[u8],
            signing_input: &[u8],
            signature: &[u8],
        ) -> Result<()> {
            if signature == &signing_input[..8.min(signing_input.len())] {
                Ok(())
            } else {
                Err(TokenError::SignatureInvalid)
            }
        }
    }

    #[test]
    fn binary_and_compact_round_trip() {
        let header = TokenHeader::new(TokenProfile::Access, TokenAlgorithm::DeploymentDefined);
        let mut claims = AegisClaims::new("issuer", "subject", "audience");
        claims.issued_at_ns = 10;
        claims.not_before_ns = 10;
        claims.expires_at_ns = 100;
        claims.schema_id = SchemaId::new([7; 16]);
        let mut cap = CapabilityClaim::new(42, "billing.capture_payment");
        cap.allowed_messages.push(MessageType::new(0x2101));
        claims.capabilities.push(cap);

        let token = AegisToken::sign(header, claims, &EchoSigner).unwrap();
        let binary = token.encode_binary();
        let decoded = AegisToken::decode_binary(&binary).unwrap();
        assert_eq!(decoded, token);

        let compact = token.encode_compact();
        let decoded = AegisToken::decode_compact(&compact).unwrap();
        assert_eq!(decoded, token);

        let mut ctx = ValidationContext::new(50);
        ctx.required_audience = Some("audience");
        ctx.required_capability_id = Some(42);
        ctx.required_message_type = Some(MessageType::new(0x2101));
        decoded.verify_and_validate(&EchoVerifier, &ctx).unwrap();
    }
}
