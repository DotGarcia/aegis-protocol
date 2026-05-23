//! IDL semantic validation.

use std::collections::HashSet;

use crate::ast::{Document, FieldPresence};
use crate::IdlError;

/// Validates semantic safety rules for a parsed document.
pub fn validate_document(document: &Document) -> Result<(), IdlError> {
    let mut message_names = HashSet::new();
    let mut message_types = HashSet::new();
    let mut capability_names = HashSet::new();
    let mut state_names = HashSet::new();

    for message in &document.messages {
        if !message_names.insert(message.name.as_str()) {
            return Err(IdlError::new(
                0,
                format!("duplicate message `{}`", message.name),
            ));
        }
        if !message_types.insert(message.type_id) {
            return Err(IdlError::new(
                0,
                format!("duplicate message type 0x{:x}", message.type_id),
            ));
        }
    }

    for capability in &document.capabilities {
        if !capability_names.insert(capability.name.as_str()) {
            return Err(IdlError::new(
                0,
                format!("duplicate capability `{}`", capability.name),
            ));
        }
        for scope in &capability.scopes {
            if scope.name.is_empty() || scope.ty.is_empty() {
                return Err(IdlError::new(
                    0,
                    format!("invalid scope in capability `{}`", capability.name),
                ));
            }
        }
    }

    for state in &document.states {
        if !state_names.insert(state.name.as_str()) {
            return Err(IdlError::new(
                0,
                format!("duplicate state `{}`", state.name),
            ));
        }
    }

    for state in &document.states {
        for transition in &state.transitions {
            if !message_names.contains(transition.message.as_str()) {
                return Err(IdlError::new(
                    0,
                    format!(
                        "state `{}` allows unknown message `{}`",
                        state.name, transition.message
                    ),
                ));
            }
            if let Some(capability) = &transition.capability {
                if !capability_names.contains(capability.as_str()) {
                    return Err(IdlError::new(
                        0,
                        format!(
                            "state `{}` references unknown capability `{capability}`",
                            state.name
                        ),
                    ));
                }
            }
            if let Some(next_state) = &transition.next_state {
                if !state_names.contains(next_state.as_str()) {
                    return Err(IdlError::new(
                        0,
                        format!(
                            "state `{}` transitions to unknown state `{next_state}`",
                            state.name
                        ),
                    ));
                }
            }
        }
    }

    for message in &document.messages {
        if message.type_id == 0 {
            return Err(IdlError::new(
                0,
                format!("message `{}` uses reserved type id 0", message.name),
            ));
        }
        if message.max_size.is_none() {
            return Err(IdlError::new(
                0,
                format!("message `{}` requires @max_size(...)", message.name),
            ));
        }
        if let Some(capability) = &message.contract.requires_capability {
            if !capability_names.contains(capability.as_str()) {
                return Err(IdlError::new(
                    0,
                    format!(
                        "message `{}` requires unknown capability `{capability}`",
                        message.name
                    ),
                ));
            }
        }
        if let Some(state) = &message.contract.allowed_state {
            if !state_names.contains(state.as_str()) {
                return Err(IdlError::new(
                    0,
                    format!("message `{}` allows unknown state `{state}`", message.name),
                ));
            }
        }

        let mut field_ids = HashSet::new();
        let mut field_names = HashSet::new();
        for field in &message.fields {
            if field.id == 0 {
                return Err(IdlError::new(
                    0,
                    format!("field `{}` uses reserved id 0", field.name),
                ));
            }
            if !field_ids.insert(field.id) {
                return Err(IdlError::new(
                    0,
                    format!(
                        "message `{}` has duplicate field id {}",
                        message.name, field.id
                    ),
                ));
            }
            if !field_names.insert(field.name.as_str()) {
                return Err(IdlError::new(
                    0,
                    format!(
                        "message `{}` has duplicate field `{}`",
                        message.name, field.name
                    ),
                ));
            }
            if field.ty.is_variable()
                && field.constraints.max_len.is_none()
                && field.constraints.fixed_size.is_none()
                && !matches!(field.presence, FieldPresence::Repeated)
            {
                return Err(IdlError::new(
                    0,
                    format!(
                        "variable field `{}` in message `{}` requires `max` or `size`",
                        field.name, message.name
                    ),
                ));
            }
            if matches!(field.presence, FieldPresence::Repeated)
                && field.constraints.max_items.is_none()
            {
                return Err(IdlError::new(
                    0,
                    format!(
                        "repeated field `{}` in message `{}` requires `max_items`",
                        field.name, message.name
                    ),
                ));
            }
            if matches!(field.presence, FieldPresence::Repeated)
                && field.ty.is_variable()
                && field.constraints.item_max_len.is_none()
            {
                return Err(IdlError::new(
                    0,
                    format!(
                        "repeated variable field `{}` in message `{}` requires `item_max`",
                        field.name, message.name
                    ),
                ));
            }
            if field.ty.is_string() && !field.constraints.flags.iter().any(|flag| flag == "utf8") {
                return Err(IdlError::new(
                    0,
                    format!(
                        "string field `{}` in message `{}` should declare `utf8`",
                        field.name, message.name
                    ),
                ));
            }
        }
    }

    for state in &document.states {
        for transition in &state.transitions {
            if !message_names.contains(transition.message.as_str()) {
                return Err(IdlError::new(
                    0,
                    format!(
                        "state `{}` references unknown message `{}`",
                        state.name, transition.message
                    ),
                ));
            }
        }
    }

    Ok(())
}
