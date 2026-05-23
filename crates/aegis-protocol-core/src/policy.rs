//! Security, privacy and logging policy enums.

/// Security profile requested by a schema or session.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityProfile {
    /// Balanced default profile.
    Core = 0,
    /// Edge/mobile/IoT profile.
    Edge = 1,
    /// Realtime profile.
    Realtime = 2,
    /// Bulk-data profile.
    Bulk = 3,
    /// Hardened profile for sensitive environments.
    Hardened = 4,
    /// Zero-trust profile requiring capabilities on every operation.
    ZeroTrust = 5,
}

/// Sensitivity of a field for policy and logging.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    /// Safe to log in plaintext.
    Safe = 0,
    /// Personally identifiable information.
    Pii = 1,
    /// Secret or credential material.
    Secret = 2,
    /// Length or timing-sensitive data.
    LengthSensitive = 3,
}

/// How a field may appear in logs.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldLogPolicy {
    /// Log the field value as-is.
    SafeLog = 0,
    /// Redact the field value.
    Redact = 1,
    /// Log only a hash or fingerprint.
    HashLog = 2,
    /// Never log this field.
    NoLog = 3,
}
