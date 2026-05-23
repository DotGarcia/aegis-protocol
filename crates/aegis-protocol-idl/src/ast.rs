//! IDL abstract syntax tree.

/// Parsed Aegis IDL document.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Document {
    /// Optional package name.
    pub package: Option<String>,
    /// Capability declarations.
    pub capabilities: Vec<Capability>,
    /// Session state declarations.
    pub states: Vec<State>,
    /// Parsed messages.
    pub messages: Vec<Message>,
}

/// Capability declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    /// Capability name.
    pub name: String,
    /// Scoped field requirements.
    pub scopes: Vec<Scope>,
    /// Whether expiry is required.
    pub expires_required: bool,
    /// Replay window token, for example `10m`.
    pub replay_window: Option<String>,
}

/// Capability scope declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// Scope field name.
    pub name: String,
    /// Scope field type.
    pub ty: String,
}

/// Session state declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    /// State name.
    pub name: String,
    /// Allowed transitions from this state.
    pub transitions: Vec<StateTransition>,
}

/// Allowed message transition inside a state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateTransition {
    /// Message allowed in this state.
    pub message: String,
    /// Capability required by this transition.
    pub capability: Option<String>,
    /// Optional next state.
    pub next_state: Option<String>,
}

/// Message declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Message name.
    pub name: String,
    /// Stable numeric message type.
    pub type_id: u32,
    /// Optional maximum encoded message size.
    pub max_size: Option<u32>,
    /// Operational contract attached to this message.
    pub contract: MessageContract,
    /// Message fields.
    pub fields: Vec<Field>,
}

/// Operational contract parsed from message attributes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MessageContract {
    /// CPU budget token, for example `1ms`.
    pub cpu_budget: Option<String>,
    /// Memory budget token, for example `4kb`.
    pub memory_budget: Option<String>,
    /// Capability required by this message.
    pub requires_capability: Option<String>,
    /// Session state where this message is allowed.
    pub allowed_state: Option<String>,
    /// Idempotency policy token.
    pub idempotency: Option<String>,
    /// Security profile token.
    pub security: Option<String>,
}

/// Field declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// Required/optional/repeated field presence.
    pub presence: FieldPresence,
    /// Field type.
    pub ty: FieldType,
    /// Field name.
    pub name: String,
    /// Stable field id.
    pub id: u32,
    /// Size and validation constraints.
    pub constraints: FieldConstraints,
    /// Security/logging policy annotations without the `@` prefix.
    pub policies: Vec<String>,
}

/// Presence modifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldPresence {
    /// Required field.
    Required,
    /// Optional field.
    Optional,
    /// Repeated field.
    Repeated,
}

/// Supported field type tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldType {
    /// Boolean.
    Bool,
    /// Unsigned 8-bit integer.
    U8,
    /// Unsigned 16-bit integer.
    U16,
    /// Unsigned 32-bit integer.
    U32,
    /// Unsigned 64-bit integer.
    U64,
    /// Unsigned 128-bit integer.
    U128,
    /// Signed 8-bit integer.
    I8,
    /// Signed 16-bit integer.
    I16,
    /// Signed 32-bit integer.
    I32,
    /// Signed 64-bit integer.
    I64,
    /// Signed 128-bit integer.
    I128,
    /// 32-bit float.
    F32,
    /// 64-bit float.
    F64,
    /// Decimal 128-bit value.
    Decimal128,
    /// Money value represented by fixed precision contract.
    Money,
    /// Nanosecond timestamp.
    TimestampNs,
    /// Nanosecond duration.
    DurationNs,
    /// UUID represented as 128 bits.
    Uuid128,
    /// 256-bit hash.
    Hash256,
    /// Signature bytes.
    Signature,
    /// IP address bytes.
    IpAddr,
    /// Geographic point.
    GeoPoint,
    /// Raw bytes.
    Bytes,
    /// UTF-8 string.
    String,
    /// Custom or future type.
    Custom(String),
}

impl FieldType {
    /// Parses a field type token.
    pub fn parse(token: &str) -> Self {
        match token {
            "bool" => Self::Bool,
            "u8" => Self::U8,
            "u16" => Self::U16,
            "u32" => Self::U32,
            "u64" => Self::U64,
            "u128" => Self::U128,
            "i8" => Self::I8,
            "i16" => Self::I16,
            "i32" => Self::I32,
            "i64" => Self::I64,
            "i128" => Self::I128,
            "f32" => Self::F32,
            "f64" => Self::F64,
            "decimal128" => Self::Decimal128,
            "money" => Self::Money,
            "timestamp_ns" => Self::TimestampNs,
            "duration_ns" => Self::DurationNs,
            "uuid128" => Self::Uuid128,
            "hash256" => Self::Hash256,
            "signature" => Self::Signature,
            "ip_addr" => Self::IpAddr,
            "geo_point" => Self::GeoPoint,
            "bytes" => Self::Bytes,
            "string" => Self::String,
            other => Self::Custom(other.to_owned()),
        }
    }

    /// Returns true when this type is variable-sized on the wire.
    pub fn is_variable(&self) -> bool {
        matches!(
            self,
            Self::Bytes | Self::String | Self::Signature | Self::Custom(_)
        )
    }

    /// Returns true when this type is UTF-8 text.
    pub fn is_string(&self) -> bool {
        matches!(self, Self::String)
    }
}

/// Field validation constraints.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FieldConstraints {
    /// Maximum string or bytes length.
    pub max_len: Option<u32>,
    /// Exact size requirement.
    pub fixed_size: Option<u32>,
    /// Maximum number of repeated items.
    pub max_items: Option<u32>,
    /// Maximum size for a repeated item.
    pub item_max_len: Option<u32>,
    /// Free-form validation flags such as `utf8` or `no_control_chars`.
    pub flags: Vec<String>,
}
