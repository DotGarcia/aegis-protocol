//! Operation identity and tracing identifiers.

/// Stable operation identifier for idempotency and deduplication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OperationId([u8; 16]);

impl OperationId {
    /// Creates an operation id from raw bytes.
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Trace identifier propagated across Aegis operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceId([u8; 16]);

impl TraceId {
    /// Creates a trace id from raw bytes.
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Causal parent relationship for retries, streams and event chains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CausalId([u8; 16]);

impl CausalId {
    /// Creates a causal id from raw bytes.
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}
