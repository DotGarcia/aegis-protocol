//! Canonical schema rendering and development fingerprints.

use crate::ast::{Document, FieldPresence, FieldType};

/// Renders a deterministic canonical representation of a document.
pub fn canonical_document(document: &Document) -> String {
    let mut out = String::new();
    if let Some(package) = &document.package {
        out.push_str("package ");
        out.push_str(package);
        out.push('\n');
    }

    for capability in &document.capabilities {
        out.push_str("capability ");
        out.push_str(&capability.name);
        out.push('\n');
        for scope in &capability.scopes {
            out.push_str("scope ");
            out.push_str(&scope.name);
            out.push(':');
            out.push_str(&scope.ty);
            out.push('\n');
        }
        if capability.expires_required {
            out.push_str("expires required\n");
        }
        if let Some(window) = &capability.replay_window {
            out.push_str("replay_window ");
            out.push_str(window);
            out.push('\n');
        }
    }

    for state in &document.states {
        out.push_str("state ");
        out.push_str(&state.name);
        out.push('\n');
        for transition in &state.transitions {
            out.push_str("allow ");
            out.push_str(&transition.message);
            if let Some(capability) = &transition.capability {
                out.push_str(" using ");
                out.push_str(capability);
            }
            if let Some(next_state) = &transition.next_state {
                out.push_str(" -> ");
                out.push_str(next_state);
            }
            out.push('\n');
        }
    }

    for message in &document.messages {
        out.push_str("message ");
        out.push_str(&message.name);
        out.push_str(" type=");
        out.push_str(&message.type_id.to_string());
        if let Some(max_size) = message.max_size {
            out.push_str(" max_size=");
            out.push_str(&max_size.to_string());
        }
        if let Some(value) = &message.contract.requires_capability {
            out.push_str(" requires_capability=");
            out.push_str(value);
        }
        if let Some(value) = &message.contract.allowed_state {
            out.push_str(" allowed_state=");
            out.push_str(value);
        }
        if let Some(value) = &message.contract.security {
            out.push_str(" security=");
            out.push_str(value);
        }
        if let Some(value) = &message.contract.idempotency {
            out.push_str(" idempotency=");
            out.push_str(value);
        }
        out.push('\n');
        for field in &message.fields {
            out.push_str("field ");
            out.push_str(match field.presence {
                FieldPresence::Required => "required",
                FieldPresence::Optional => "optional",
                FieldPresence::Repeated => "repeated",
            });
            out.push(' ');
            out.push_str(type_name(&field.ty));
            out.push(' ');
            out.push_str(&field.name);
            out.push_str(" id=");
            out.push_str(&field.id.to_string());
            if let Some(value) = field.constraints.max_len {
                out.push_str(" max=");
                out.push_str(&value.to_string());
            }
            if let Some(value) = field.constraints.fixed_size {
                out.push_str(" size=");
                out.push_str(&value.to_string());
            }
            if let Some(value) = field.constraints.max_items {
                out.push_str(" max_items=");
                out.push_str(&value.to_string());
            }
            if let Some(value) = field.constraints.item_max_len {
                out.push_str(" item_max=");
                out.push_str(&value.to_string());
            }
            for flag in &field.constraints.flags {
                out.push(' ');
                out.push_str(flag);
            }
            for policy in &field.policies {
                out.push_str(" @");
                out.push_str(policy);
            }
            out.push('\n');
        }
    }

    out
}

/// Computes a deterministic 128-bit development fingerprint.
///
/// This is intentionally dependency-free for the MVP. It is not a replacement
/// for a cryptographic schema hash in hardened deployments.
pub fn schema_fingerprint(document: &Document) -> [u8; 16] {
    let canonical = canonical_document(document);
    fingerprint_bytes(canonical.as_bytes())
}

/// Returns a 32-character lowercase hex string for a fingerprint.
pub fn fingerprint_hex(bytes: [u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn fingerprint_bytes(bytes: &[u8]) -> [u8; 16] {
    let mut a: u64 = 0xcbf2_9ce4_8422_2325;
    let mut b: u64 = 0x1000_0000_01b3_0001;
    for byte in bytes {
        a ^= *byte as u64;
        a = a.wrapping_mul(0x0000_0100_0000_01b3);
        b ^= a.rotate_left(13) ^ (*byte as u64);
        b = b.wrapping_mul(0x9e37_79b1_85eb_ca87);
    }
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&a.to_le_bytes());
    out[8..16].copy_from_slice(&b.to_le_bytes());
    out
}

fn type_name(ty: &FieldType) -> &str {
    match ty {
        FieldType::Bool => "bool",
        FieldType::U8 => "u8",
        FieldType::U16 => "u16",
        FieldType::U32 => "u32",
        FieldType::U64 => "u64",
        FieldType::U128 => "u128",
        FieldType::I8 => "i8",
        FieldType::I16 => "i16",
        FieldType::I32 => "i32",
        FieldType::I64 => "i64",
        FieldType::I128 => "i128",
        FieldType::F32 => "f32",
        FieldType::F64 => "f64",
        FieldType::Decimal128 => "decimal128",
        FieldType::Money => "money",
        FieldType::TimestampNs => "timestamp_ns",
        FieldType::DurationNs => "duration_ns",
        FieldType::Uuid128 => "uuid128",
        FieldType::Hash256 => "hash256",
        FieldType::Signature => "signature",
        FieldType::IpAddr => "ip_addr",
        FieldType::GeoPoint => "geo_point",
        FieldType::Bytes => "bytes",
        FieldType::String => "string",
        FieldType::Custom(name) => name.as_str(),
    }
}
