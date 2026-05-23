//! Minimal line-oriented IDL parser.

use crate::ast::{
    Capability, Document, Field, FieldConstraints, FieldPresence, FieldType, Message,
    MessageContract, Scope, State, StateTransition,
};
use crate::IdlError;

/// Parses an Aegis IDL document.
pub fn parse_document(input: &str) -> Result<Document, IdlError> {
    let mut document = Document::default();
    let mut block: Option<Block> = None;

    for (idx, raw_line) in input.lines().enumerate() {
        let line_no = idx + 1;
        let mut line = raw_line.split("//").next().unwrap_or("").trim().to_owned();
        if line.is_empty() {
            continue;
        }

        if line == "{" {
            continue;
        }

        if line == "}" {
            close_block(&mut document, &mut block, line_no)?;
            continue;
        }

        if line.ends_with('{') {
            line.truncate(line.len() - 1);
            line = line.trim().to_owned();
        }

        match block.as_mut() {
            Some(Block::Message(message)) => {
                let field = parse_field(&line, line_no)?;
                message.fields.push(field);
            }
            Some(Block::Capability(capability)) => {
                parse_capability_line(capability, &line, line_no)?
            }
            Some(Block::State(state)) => parse_state_line(state, &line, line_no)?,
            None => parse_top_level(&mut document, &mut block, &line, line_no)?,
        }
    }

    if block.is_some() {
        return Err(IdlError::new(input.lines().count(), "unclosed block"));
    }

    Ok(document)
}

#[derive(Debug)]
enum Block {
    Message(Message),
    Capability(Capability),
    State(State),
}

fn close_block(
    document: &mut Document,
    block: &mut Option<Block>,
    line_no: usize,
) -> Result<(), IdlError> {
    match block.take() {
        Some(Block::Message(message)) => document.messages.push(message),
        Some(Block::Capability(capability)) => document.capabilities.push(capability),
        Some(Block::State(state)) => document.states.push(state),
        None => return Err(IdlError::new(line_no, "unexpected closing brace")),
    }
    Ok(())
}

fn parse_top_level(
    document: &mut Document,
    block: &mut Option<Block>,
    line: &str,
    line_no: usize,
) -> Result<(), IdlError> {
    if let Some(package) = line.strip_prefix("package ") {
        let package = package.trim().trim_end_matches(';').to_owned();
        if package.is_empty() {
            return Err(IdlError::new(line_no, "empty package name"));
        }
        document.package = Some(package);
        return Ok(());
    }

    if line.starts_with("capability ") {
        *block = Some(Block::Capability(parse_capability_header(line, line_no)?));
        return Ok(());
    }

    if line.starts_with("state ") {
        *block = Some(Block::State(parse_state_header(line, line_no)?));
        return Ok(());
    }

    if line.starts_with("message ") {
        *block = Some(Block::Message(parse_message_header(line, line_no)?));
        return Ok(());
    }

    Err(IdlError::new(line_no, format!("unexpected line: {line}")))
}

fn parse_capability_header(line: &str, line_no: usize) -> Result<Capability, IdlError> {
    let rest = line.strip_prefix("capability ").unwrap().trim();
    let name = rest
        .split_whitespace()
        .next()
        .ok_or_else(|| IdlError::new(line_no, "missing capability name"))?;
    Ok(Capability {
        name: name.to_owned(),
        scopes: Vec::new(),
        expires_required: false,
        replay_window: None,
    })
}

fn parse_capability_line(
    capability: &mut Capability,
    line: &str,
    line_no: usize,
) -> Result<(), IdlError> {
    let line = line.trim_end_matches(';').trim();
    if let Some(scope) = line.strip_prefix("scope ") {
        let (name, ty) = scope
            .split_once(':')
            .ok_or_else(|| IdlError::new(line_no, "scope requires name:type"))?;
        capability.scopes.push(Scope {
            name: name.trim().to_owned(),
            ty: ty.trim().to_owned(),
        });
        return Ok(());
    }
    if let Some(expires) = line.strip_prefix("expires ") {
        capability.expires_required = expires.trim() == "required";
        return Ok(());
    }
    if let Some(window) = line.strip_prefix("replay_window ") {
        capability.replay_window = Some(window.trim().to_owned());
        return Ok(());
    }
    Err(IdlError::new(
        line_no,
        format!("unknown capability item: {line}"),
    ))
}

fn parse_state_header(line: &str, line_no: usize) -> Result<State, IdlError> {
    let rest = line.strip_prefix("state ").unwrap().trim();
    let name = rest
        .split_whitespace()
        .next()
        .ok_or_else(|| IdlError::new(line_no, "missing state name"))?;
    Ok(State {
        name: name.to_owned(),
        transitions: Vec::new(),
    })
}

fn parse_state_line(state: &mut State, line: &str, line_no: usize) -> Result<(), IdlError> {
    let line = line.trim_end_matches(';').trim();
    let rest = line
        .strip_prefix("allow ")
        .ok_or_else(|| IdlError::new(line_no, "state line must start with `allow`"))?;
    let tokens: Vec<&str> = rest.split_whitespace().collect();
    if tokens.is_empty() {
        return Err(IdlError::new(line_no, "allow requires a message name"));
    }
    let mut transition = StateTransition {
        message: tokens[0].to_owned(),
        capability: None,
        next_state: None,
    };
    let mut i = 1;
    while i < tokens.len() {
        match tokens[i] {
            "using" => {
                i += 1;
                let cap = tokens
                    .get(i)
                    .ok_or_else(|| IdlError::new(line_no, "missing capability after using"))?;
                transition.capability = Some(cap.trim_end_matches(';').to_owned());
            }
            "->" => {
                i += 1;
                let state = tokens
                    .get(i)
                    .ok_or_else(|| IdlError::new(line_no, "missing next state after ->"))?;
                transition.next_state = Some(state.trim_end_matches(';').to_owned());
            }
            other => {
                return Err(IdlError::new(
                    line_no,
                    format!("unexpected state token `{other}`"),
                ))
            }
        }
        i += 1;
    }
    state.transitions.push(transition);
    Ok(())
}

fn parse_message_header(line: &str, line_no: usize) -> Result<Message, IdlError> {
    let rest = line.strip_prefix("message ").unwrap().trim();
    let name = rest
        .split_whitespace()
        .next()
        .ok_or_else(|| IdlError::new(line_no, "missing message name"))?;

    let type_id = find_attr_u32(rest, "@type", line_no)?
        .ok_or_else(|| IdlError::new(line_no, "message requires @type(...)"))?;
    let max_size = find_attr_u32(rest, "@max_size", line_no)?;
    let contract = MessageContract {
        cpu_budget: find_attr_string(rest, "@cpu_budget")?,
        memory_budget: find_attr_string(rest, "@memory_budget")?,
        requires_capability: find_attr_string(rest, "@requires_capability")?,
        allowed_state: find_attr_string(rest, "@allowed_state")?,
        idempotency: find_attr_string(rest, "@idempotent")?,
        security: find_attr_string(rest, "@security")?,
    };

    Ok(Message {
        name: name.to_owned(),
        type_id,
        max_size,
        contract,
        fields: Vec::new(),
    })
}

fn parse_field(line: &str, line_no: usize) -> Result<Field, IdlError> {
    let line = line.trim_end_matches(';');
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 5 {
        return Err(IdlError::new(
            line_no,
            "field requires: <presence> <type> <name> = <id>",
        ));
    }

    let presence = match tokens[0] {
        "required" => FieldPresence::Required,
        "optional" => FieldPresence::Optional,
        "repeated" => FieldPresence::Repeated,
        other => {
            return Err(IdlError::new(
                line_no,
                format!("unknown field presence `{other}`"),
            ))
        }
    };

    if tokens[3] != "=" {
        return Err(IdlError::new(line_no, "expected `=` before field id"));
    }

    let mut constraints = FieldConstraints::default();
    let mut policies = Vec::new();
    let mut i = 5;
    while i < tokens.len() {
        let token = tokens[i].trim_end_matches(';');
        match token {
            "max" => {
                i += 1;
                constraints.max_len = Some(parse_next_u32(tokens.get(i), line_no, "max")?);
            }
            "size" => {
                i += 1;
                constraints.fixed_size = Some(parse_next_u32(tokens.get(i), line_no, "size")?);
            }
            "max_items" => {
                i += 1;
                constraints.max_items = Some(parse_next_u32(tokens.get(i), line_no, "max_items")?);
            }
            "item_max" => {
                i += 1;
                constraints.item_max_len =
                    Some(parse_next_u32(tokens.get(i), line_no, "item_max")?);
            }
            annotation if annotation.starts_with('@') => {
                policies.push(annotation.trim_start_matches('@').to_owned());
            }
            flag => constraints.flags.push(flag.to_owned()),
        }
        i += 1;
    }

    Ok(Field {
        presence,
        ty: FieldType::parse(tokens[1]),
        name: tokens[2].to_owned(),
        id: parse_u32(tokens[4].trim_end_matches(';'), line_no)?,
        constraints,
        policies,
    })
}

fn find_attr_u32(input: &str, attr: &str, line_no: usize) -> Result<Option<u32>, IdlError> {
    let Some(value) = find_attr_string(input, attr)? else {
        return Ok(None);
    };
    Ok(Some(parse_u32(&value, line_no)?))
}

fn find_attr_string(input: &str, attr: &str) -> Result<Option<String>, IdlError> {
    let marker = format!("{attr}(");
    let Some(start) = input.find(&marker) else {
        return Ok(None);
    };
    let value_start = start + marker.len();
    let Some(relative_end) = input[value_start..].find(')') else {
        return Err(IdlError::new(0, format!("unterminated {attr}(...)")));
    };
    Ok(Some(
        input[value_start..value_start + relative_end]
            .trim()
            .to_owned(),
    ))
}

fn parse_next_u32(token: Option<&&str>, line_no: usize, name: &str) -> Result<u32, IdlError> {
    let token = token.ok_or_else(|| IdlError::new(line_no, format!("missing value for {name}")))?;
    parse_u32(token.trim_end_matches(';'), line_no)
}

fn parse_u32(token: &str, line_no: usize) -> Result<u32, IdlError> {
    let token = token.trim();
    if let Some(hex) = token.strip_prefix("0x") {
        u32::from_str_radix(hex, 16)
            .map_err(|_| IdlError::new(line_no, format!("invalid integer `{token}`")))
    } else {
        token
            .parse::<u32>()
            .map_err(|_| IdlError::new(line_no, format!("invalid integer `{token}`")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_message_capability_and_state() {
        let input = r#"
            package billing.v1;
            capability billing.capture_payment {
              scope merchant_id:u64;
              expires required;
              replay_window 10m;
            }
            state Authenticated {
              allow CapturePayment using billing.capture_payment;
            }
            message CapturePayment @type(0x2101) @max_size(1024) @requires_capability(billing.capture_payment) @allowed_state(Authenticated) {
              required u64 merchant_id = 1;
              optional string reference = 6 max 128 utf8 @safe_log;
            }
        "#;
        let doc = parse_document(input).unwrap();
        assert_eq!(doc.package.as_deref(), Some("billing.v1"));
        assert_eq!(doc.capabilities.len(), 1);
        assert_eq!(doc.states.len(), 1);
        assert_eq!(doc.messages.len(), 1);
        assert_eq!(doc.messages[0].type_id, 0x2101);
        assert_eq!(
            doc.messages[0].contract.allowed_state.as_deref(),
            Some("Authenticated")
        );
        assert_eq!(doc.messages[0].fields.len(), 2);
    }
}
