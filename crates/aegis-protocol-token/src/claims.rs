//! Aegis Capability Token headers, claims and validation policy.

use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryFrom;

use aegis_protocol_core::{BudgetClass, MessageType, SchemaId, SecurityProfile};

use crate::algorithm::{TokenAlgorithm, TokenProfile};
use crate::codec::{
    push_bytes, push_string, push_u16, push_u32, push_u64, Cursor, MAX_CAPABILITIES,
    MAX_CAPABILITY_NAME_BYTES, MAX_IDENTITY_BYTES, MAX_KEY_ID_BYTES, MAX_MESSAGES_PER_CAPABILITY,
    MAX_SCOPE_BYTES,
};
use crate::flags::{CapabilityFlags, TokenFlags};
use crate::{Result, TokenError};

/// Protected ACT header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenHeader {
    /// Token profile.
    pub profile: TokenProfile,
    /// Signature algorithm identifier.
    pub algorithm: TokenAlgorithm,
    /// Token flags.
    pub flags: TokenFlags,
    /// Key identifier used by the verifier to select a key.
    pub key_id: Vec<u8>,
    /// Optional issuer hint for key lookup. It is not trusted before signature verification.
    pub issuer_hint: String,
}

impl TokenHeader {
    /// Creates a new token header.
    pub fn new(profile: TokenProfile, algorithm: TokenAlgorithm) -> Self {
        Self {
            profile,
            algorithm,
            flags: TokenFlags::EMPTY,
            key_id: Vec::new(),
            issuer_hint: String::new(),
        }
    }

    /// Encodes this header into deterministic binary form.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.profile as u8);
        out.push(self.algorithm as u8);
        push_u16(&mut out, self.flags.bits());
        push_bytes(&mut out, &self.key_id);
        push_string(&mut out, &self.issuer_hint);
        out
    }

    /// Decodes a protected header.
    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(input);
        let profile = TokenProfile::try_from(cursor.u8()?)?;
        let algorithm = TokenAlgorithm::try_from(cursor.u8()?)?;
        let flags = TokenFlags::from_bits(cursor.u16()?);
        let key_id = cursor.bytes(MAX_KEY_ID_BYTES)?;
        let issuer_hint = cursor.string(MAX_IDENTITY_BYTES)?;
        if !cursor.is_finished() {
            return Err(TokenError::MalformedToken);
        }
        Ok(Self {
            profile,
            algorithm,
            flags,
            key_id,
            issuer_hint,
        })
    }
}

/// One capability claim inside an ACT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityClaim {
    /// Stable capability identifier. Deployments should derive this from canonical capability metadata.
    pub capability_id: u64,
    /// Human-readable capability name for diagnostics.
    pub name: String,
    /// Binary scope blob interpreted by the application schema.
    pub scope: Vec<u8>,
    /// Capability-specific expiration in unix nanoseconds. Zero means token-level expiration only.
    pub expires_at_ns: u64,
    /// Capability flags.
    pub flags: CapabilityFlags,
    /// Explicit allow-list of message types this capability covers.
    pub allowed_messages: Vec<MessageType>,
}

impl CapabilityClaim {
    /// Creates a capability claim with no scope and no message bindings.
    pub fn new(capability_id: u64, name: impl Into<String>) -> Self {
        Self {
            capability_id,
            name: name.into(),
            scope: Vec::new(),
            expires_at_ns: 0,
            flags: CapabilityFlags::EMPTY,
            allowed_messages: Vec::new(),
        }
    }

    /// Returns true if this capability covers a message type.
    pub fn allows_message(&self, message_type: MessageType) -> bool {
        self.allowed_messages
            .iter()
            .copied()
            .any(|item| item == message_type)
    }

    /// Returns true if the capability is time-valid at `now_unix_ns`.
    pub const fn is_time_valid(
        &self,
        now_unix_ns: u64,
        token_expires_at_ns: u64,
        skew_ns: u64,
    ) -> bool {
        let effective_expiry =
            if self.expires_at_ns == 0 || self.expires_at_ns > token_expires_at_ns {
                token_expires_at_ns
            } else {
                self.expires_at_ns
            };
        now_unix_ns <= effective_expiry.saturating_add(skew_ns)
    }
}

/// ACT claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AegisClaims {
    /// Token issuer.
    pub issuer: String,
    /// Subject receiving the capability.
    pub subject: String,
    /// Intended audience.
    pub audience: String,
    /// Issued-at timestamp in unix nanoseconds.
    pub issued_at_ns: u64,
    /// Not-before timestamp in unix nanoseconds.
    pub not_before_ns: u64,
    /// Expiration timestamp in unix nanoseconds.
    pub expires_at_ns: u64,
    /// Unique token identifier for replay/dedup tracking.
    pub token_id: [u8; 16],
    /// Schema fingerprint this token is bound to.
    pub schema_id: SchemaId,
    /// Maximum budget class allowed by this token.
    pub max_budget_class: BudgetClass,
    /// Security profile requested by this token.
    pub security_profile: SecurityProfile,
    /// Capability claims carried by the token.
    pub capabilities: Vec<CapabilityClaim>,
}

impl AegisClaims {
    /// Creates minimal claims with no capabilities.
    pub fn new(
        issuer: impl Into<String>,
        subject: impl Into<String>,
        audience: impl Into<String>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            subject: subject.into(),
            audience: audience.into(),
            issued_at_ns: 0,
            not_before_ns: 0,
            expires_at_ns: 0,
            token_id: [0; 16],
            schema_id: SchemaId::zero(),
            max_budget_class: BudgetClass::Normal,
            security_profile: SecurityProfile::Core,
            capabilities: Vec::new(),
        }
    }

    /// Encodes claims into deterministic binary form.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_string(&mut out, &self.issuer);
        push_string(&mut out, &self.subject);
        push_string(&mut out, &self.audience);
        push_u64(&mut out, self.issued_at_ns);
        push_u64(&mut out, self.not_before_ns);
        push_u64(&mut out, self.expires_at_ns);
        out.extend_from_slice(&self.token_id);
        out.extend_from_slice(self.schema_id.as_bytes());
        out.push(self.max_budget_class as u8);
        out.push(self.security_profile as u8);
        crate::codec::push_varint(&mut out, self.capabilities.len() as u64);
        for capability in &self.capabilities {
            push_u64(&mut out, capability.capability_id);
            push_string(&mut out, &capability.name);
            push_bytes(&mut out, &capability.scope);
            push_u64(&mut out, capability.expires_at_ns);
            push_u16(&mut out, capability.flags.bits());
            crate::codec::push_varint(&mut out, capability.allowed_messages.len() as u64);
            for message in &capability.allowed_messages {
                push_u32(&mut out, message.get());
            }
        }
        out
    }

    /// Decodes claims from deterministic binary form.
    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(input);
        let issuer = cursor.string(MAX_IDENTITY_BYTES)?;
        let subject = cursor.string(MAX_IDENTITY_BYTES)?;
        let audience = cursor.string(MAX_IDENTITY_BYTES)?;
        let issued_at_ns = cursor.u64()?;
        let not_before_ns = cursor.u64()?;
        let expires_at_ns = cursor.u64()?;
        let mut token_id = [0u8; 16];
        token_id.copy_from_slice(cursor.take(16)?);
        let mut schema_bytes = [0u8; 16];
        schema_bytes.copy_from_slice(cursor.take(16)?);
        let schema_id = SchemaId::new(schema_bytes);
        let max_budget_class = decode_budget_class(cursor.u8()?)?;
        let security_profile = decode_security_profile(cursor.u8()?)?;
        let capability_count =
            usize::try_from(cursor.varint()?).map_err(|_| TokenError::ResourceExceeded)?;
        if capability_count > MAX_CAPABILITIES {
            return Err(TokenError::ResourceExceeded);
        }
        let mut capabilities = Vec::with_capacity(capability_count);
        for _ in 0..capability_count {
            let capability_id = cursor.u64()?;
            let name = cursor.string(MAX_CAPABILITY_NAME_BYTES)?;
            let scope = cursor.bytes(MAX_SCOPE_BYTES)?;
            let expires_at_ns = cursor.u64()?;
            let flags = CapabilityFlags::from_bits(cursor.u16()?);
            let message_count =
                usize::try_from(cursor.varint()?).map_err(|_| TokenError::ResourceExceeded)?;
            if message_count > MAX_MESSAGES_PER_CAPABILITY {
                return Err(TokenError::ResourceExceeded);
            }
            let mut allowed_messages = Vec::with_capacity(message_count);
            for _ in 0..message_count {
                allowed_messages.push(MessageType::new(cursor.u32()?));
            }
            capabilities.push(CapabilityClaim {
                capability_id,
                name,
                scope,
                expires_at_ns,
                flags,
                allowed_messages,
            });
        }
        if !cursor.is_finished() {
            return Err(TokenError::MalformedToken);
        }
        Ok(Self {
            issuer,
            subject,
            audience,
            issued_at_ns,
            not_before_ns,
            expires_at_ns,
            token_id,
            schema_id,
            max_budget_class,
            security_profile,
            capabilities,
        })
    }

    /// Validates time, audience, schema and capability requirements.
    pub fn validate(&self, ctx: &ValidationContext<'_>) -> Result<()> {
        if self.expires_at_ns == 0
            || self.not_before_ns > self.expires_at_ns
            || self.issued_at_ns > self.expires_at_ns
        {
            return Err(TokenError::MalformedToken);
        }
        if ctx.now_unix_ns.saturating_add(ctx.clock_skew_ns) < self.not_before_ns {
            return Err(TokenError::NotYetValid);
        }
        if ctx.now_unix_ns > self.expires_at_ns.saturating_add(ctx.clock_skew_ns) {
            return Err(TokenError::Expired);
        }
        if let Some(required_audience) = ctx.required_audience {
            if self.audience != required_audience {
                return Err(TokenError::AudienceMismatch);
            }
        }
        if let Some(required_schema_id) = ctx.required_schema_id {
            if self.schema_id != required_schema_id {
                return Err(TokenError::SchemaMismatch);
            }
        }

        match (ctx.required_capability_id, ctx.required_message_type) {
            (Some(capability_id), Some(message_type)) => {
                let capability = self
                    .find_capability(capability_id)
                    .ok_or(TokenError::CapabilityDenied)?;
                if !capability.is_time_valid(ctx.now_unix_ns, self.expires_at_ns, ctx.clock_skew_ns)
                    || !capability.allows_message(message_type)
                {
                    return Err(TokenError::CapabilityDenied);
                }
            }
            (Some(capability_id), None) => {
                let capability = self
                    .find_capability(capability_id)
                    .ok_or(TokenError::CapabilityDenied)?;
                if !capability.is_time_valid(ctx.now_unix_ns, self.expires_at_ns, ctx.clock_skew_ns)
                {
                    return Err(TokenError::CapabilityDenied);
                }
            }
            (None, Some(message_type)) => {
                let allowed = self.capabilities.iter().any(|capability| {
                    capability.is_time_valid(ctx.now_unix_ns, self.expires_at_ns, ctx.clock_skew_ns)
                        && capability.allows_message(message_type)
                });
                if !allowed {
                    return Err(TokenError::CapabilityDenied);
                }
            }
            (None, None) => {}
        }

        Ok(())
    }

    /// Finds a capability by stable id.
    pub fn find_capability(&self, capability_id: u64) -> Option<&CapabilityClaim> {
        self.capabilities
            .iter()
            .find(|capability| capability.capability_id == capability_id)
    }
}

/// Validation inputs supplied by the caller.
#[derive(Debug, Clone, Copy)]
pub struct ValidationContext<'a> {
    /// Current unix time in nanoseconds.
    pub now_unix_ns: u64,
    /// Accepted clock skew in nanoseconds.
    pub clock_skew_ns: u64,
    /// Required audience, if any.
    pub required_audience: Option<&'a str>,
    /// Required schema id, if any.
    pub required_schema_id: Option<SchemaId>,
    /// Required capability id, if any.
    pub required_capability_id: Option<u64>,
    /// Required message type, if any.
    pub required_message_type: Option<MessageType>,
    /// Allows the explicitly unsafe `Unsecured` algorithm.
    pub allow_unsecured: bool,
}

impl<'a> ValidationContext<'a> {
    /// Creates a validation context for the given current unix nanosecond time.
    pub const fn new(now_unix_ns: u64) -> Self {
        Self {
            now_unix_ns,
            clock_skew_ns: 0,
            required_audience: None,
            required_schema_id: None,
            required_capability_id: None,
            required_message_type: None,
            allow_unsecured: false,
        }
    }
}

fn decode_budget_class(value: u8) -> Result<BudgetClass> {
    match value {
        0 => Ok(BudgetClass::Tiny),
        1 => Ok(BudgetClass::Normal),
        2 => Ok(BudgetClass::Bulk),
        3 => Ok(BudgetClass::Privileged),
        _ => Err(TokenError::MalformedToken),
    }
}

fn decode_security_profile(value: u8) -> Result<SecurityProfile> {
    match value {
        0 => Ok(SecurityProfile::Core),
        1 => Ok(SecurityProfile::Edge),
        2 => Ok(SecurityProfile::Realtime),
        3 => Ok(SecurityProfile::Bulk),
        4 => Ok(SecurityProfile::Hardened),
        5 => Ok(SecurityProfile::ZeroTrust),
        _ => Err(TokenError::MalformedToken),
    }
}
