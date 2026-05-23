//! Token and capability flags.

/// Bitflags carried by a token header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TokenFlags(u16);

impl TokenFlags {
    /// No flags.
    pub const EMPTY: Self = Self(0);
    /// Token may be delegated into narrower tokens if policy allows it.
    pub const DELEGABLE: Self = Self(0x0001);
    /// Token may be refreshed.
    pub const RENEWABLE: Self = Self(0x0002);
    /// Token must be used with a mutually-authenticated transport.
    pub const MTLS_BOUND: Self = Self(0x0004);
    /// Token must be used with message-envelope security.
    pub const ENVELOPE_REQUIRED: Self = Self(0x0008);
    /// Token requests hardened validation policy.
    pub const HARDENED: Self = Self(0x0010);

    /// Creates flags from raw bits.
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    /// Returns the raw flag bits.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Returns true if all `other` bits are present.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns a union of two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Bitflags attached to a capability claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapabilityFlags(u16);

impl CapabilityFlags {
    /// No flags.
    pub const EMPTY: Self = Self(0);
    /// Capability can be delegated if the token itself is delegable.
    pub const DELEGABLE: Self = Self(0x0001);
    /// Capability requires a message envelope.
    pub const ENVELOPE_ONLY: Self = Self(0x0002);
    /// Capability requires a hardened security profile.
    pub const HARDENED_ONLY: Self = Self(0x0004);
    /// Capability requires idempotency for state-changing operations.
    pub const IDEMPOTENCY_REQUIRED: Self = Self(0x0008);

    /// Creates flags from raw bits.
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    /// Returns the raw flag bits.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Returns true if all `other` bits are present.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns a union of two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}
