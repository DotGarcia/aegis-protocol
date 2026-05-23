//! Frame flag bitsets.

/// Bitflags carried by Aegis frame headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FrameFlags(u16);

impl FrameFlags {
    /// Payload is compressed with the negotiated codec.
    pub const COMPRESSED: Self = Self(0x0001);
    /// Message-envelope authentication is present.
    pub const ENVELOPE: Self = Self(0x0002);
    /// Payload uses canonical encoding rules.
    pub const CANONICAL: Self = Self(0x0004);
    /// Frame contains padding for length-hiding policy.
    pub const PADDED: Self = Self(0x0008);
    /// Frame should be included in audit hash chains.
    pub const AUDIT: Self = Self(0x0010);
    /// Frame carries latency-sensitive traffic.
    pub const URGENT: Self = Self(0x0020);

    /// Creates flags from raw bits.
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    /// Returns raw flag bits.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Returns true if all bits in `other` are set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns these flags with `other` set.
    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}
