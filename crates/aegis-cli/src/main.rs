use std::env;
use std::fs;
use std::process;

use aegis_protocol_codegen::generate_rust_module;
use aegis_protocol_idl::{fingerprint_hex, parse_document, schema_fingerprint, validate_document};
use aegis_protocol_token::AegisToken;
use aegis_protocol_wire::{ControlFrameHeader, HotFrameHeader};

fn main() {
    if let Err(err) = run() {
        eprintln!("aegis: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        print_usage();
        return Ok(());
    };

    match command.as_str() {
        "check" => {
            let path = args
                .next()
                .ok_or_else(|| "missing schema path".to_owned())?;
            let source =
                fs::read_to_string(&path).map_err(|e| format!("failed to read {path}: {e}"))?;
            let document = parse_document(&source).map_err(|e| e.to_string())?;
            validate_document(&document).map_err(|e| e.to_string())?;
            println!("schema ok");
            if let Some(package) = document.package.as_deref() {
                println!("package: {package}");
            }
            println!(
                "fingerprint: {}",
                fingerprint_hex(schema_fingerprint(&document))
            );
            println!("capabilities: {}", document.capabilities.len());
            for capability in &document.capabilities {
                println!(
                    "- capability {} scopes={}",
                    capability.name,
                    capability.scopes.len()
                );
            }
            println!("states: {}", document.states.len());
            for state in &document.states {
                println!(
                    "- state {} transitions={}",
                    state.name,
                    state.transitions.len()
                );
            }
            println!("messages: {}", document.messages.len());
            for message in &document.messages {
                println!(
                    "- {} type=0x{:x} fields={}",
                    message.name,
                    message.type_id,
                    message.fields.len()
                );
                if let Some(capability) = message.contract.requires_capability.as_deref() {
                    println!("  requires: {capability}");
                }
                if let Some(state) = message.contract.allowed_state.as_deref() {
                    println!("  state: {state}");
                }
            }
        }
        "fingerprint" => {
            let path = args
                .next()
                .ok_or_else(|| "missing schema path".to_owned())?;
            let source =
                fs::read_to_string(&path).map_err(|e| format!("failed to read {path}: {e}"))?;
            let document = parse_document(&source).map_err(|e| e.to_string())?;
            validate_document(&document).map_err(|e| e.to_string())?;
            println!("{}", fingerprint_hex(schema_fingerprint(&document)));
        }
        "generate" => {
            let path = args
                .next()
                .ok_or_else(|| "missing schema path".to_owned())?;
            let mut output_path: Option<String> = None;
            let mut mode_seen = false;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--rust" => mode_seen = true,
                    "-o" | "--output" => {
                        output_path =
                            Some(args.next().ok_or_else(|| {
                                "missing output path after -o/--output".to_owned()
                            })?);
                    }
                    other => return Err(format!("unknown generate option `{other}`")),
                }
            }
            if !mode_seen {
                return Err("missing --rust".to_owned());
            }
            let source =
                fs::read_to_string(&path).map_err(|e| format!("failed to read {path}: {e}"))?;
            let document = parse_document(&source).map_err(|e| e.to_string())?;
            validate_document(&document).map_err(|e| e.to_string())?;
            let generated = generate_rust_module(&document);
            if let Some(output_path) = output_path {
                fs::write(&output_path, generated)
                    .map_err(|e| format!("failed to write {output_path}: {e}"))?;
            } else {
                print!("{generated}");
            }
        }
        "token-inspect" => {
            let path = args.next().ok_or_else(|| "missing token path".to_owned())?;
            let bytes = fs::read(&path).map_err(|e| format!("failed to read {path}: {e}"))?;
            let token = if bytes.starts_with(b"ACT1") {
                AegisToken::decode_binary(&bytes).map_err(|e| format!("invalid binary ACT: {e}"))?
            } else {
                let text = std::str::from_utf8(&bytes)
                    .map_err(|_| "token is neither binary ACT nor UTF-8 compact ACT".to_owned())?;
                AegisToken::decode_compact(text.trim())
                    .map_err(|e| format!("invalid compact ACT: {e}"))?
            };
            println!("Aegis Capability Token");
            println!("profile: {:?}", token.header.profile);
            println!("algorithm: {:?}", token.header.algorithm);
            println!("flags: 0x{:04x}", token.header.flags.bits());
            println!("key_id_len: {}", token.header.key_id.len());
            if !token.header.issuer_hint.is_empty() {
                println!("issuer_hint: {}", token.header.issuer_hint);
            }
            println!("issuer: {}", token.claims.issuer);
            println!("subject: {}", token.claims.subject);
            println!("audience: {}", token.claims.audience);
            println!("issued_at_ns: {}", token.claims.issued_at_ns);
            println!("not_before_ns: {}", token.claims.not_before_ns);
            println!("expires_at_ns: {}", token.claims.expires_at_ns);
            println!("schema_id: {}", token.claims.schema_id);
            println!("max_budget_class: {:?}", token.claims.max_budget_class);
            println!("security_profile: {:?}", token.claims.security_profile);
            println!("capabilities: {}", token.claims.capabilities.len());
            for capability in &token.claims.capabilities {
                println!(
                    "- {} id={} scope_bytes={} messages={}",
                    capability.name,
                    capability.capability_id,
                    capability.scope.len(),
                    capability.allowed_messages.len()
                );
                for message in &capability.allowed_messages {
                    println!("  message: {}", message);
                }
            }
            println!("signature_len: {}", token.signature.len());
        }
        "inspect" => {
            let mut hot = false;
            let mut path: Option<String> = None;
            for arg in args {
                match arg.as_str() {
                    "--hot" => hot = true,
                    other => path = Some(other.to_owned()),
                }
            }
            let path = path.ok_or_else(|| "missing frame path".to_owned())?;
            let bytes = fs::read(&path).map_err(|e| format!("failed to read {path}: {e}"))?;
            if hot {
                let (header, used) = HotFrameHeader::decode(&bytes)
                    .map_err(|err| format!("not a valid Aegis hot frame: {err}"))?;
                println!("hot frame ok");
                println!("header_len: {used}");
                println!("flags: {}", header.flags);
                println!("stream_slot: {}", header.stream_slot);
                println!("type_slot: {}", header.type_slot);
                println!("capability_slot: {}", header.capability_slot);
                println!("budget_slot: {}", header.budget_slot);
                println!("seq_delta: {}", header.seq_delta);
                println!("payload_len: {}", header.payload_len);
            } else {
                let header = ControlFrameHeader::decode(&bytes)
                    .map_err(|err| format!("not a valid Aegis control frame: {err}"))?;
                println!("control frame ok");
                println!("version: {}", header.version);
                println!("flags: {}", header.flags);
                println!("connection_id: {}", header.connection_id);
                println!("stream_id: {}", header.stream_id);
                println!("message_type: 0x{:x}", header.message_type);
                println!("schema_id: {}", header.schema_id);
                println!("sequence: {}", header.sequence);
                println!("payload_len: {}", header.payload_len);
                println!("budget_slot: {}", header.budget_slot);
                println!("codec: {}", header.codec);
                println!("security_mode: {}", header.security_mode);
            }
        }
        "help" | "--help" | "-h" => print_usage(),
        other => return Err(format!("unknown command `{other}`")),
    }

    Ok(())
}

fn print_usage() {
    println!("Aegis Protocol CLI");
    println!();
    println!("Usage:");
    println!("  aegis check <schema.aegis>");
    println!("  aegis fingerprint <schema.aegis>");
    println!("  aegis generate <schema.aegis> --rust [-o generated.rs]");
    println!("  aegis inspect [--hot] <frame.bin>");
    println!("  aegis token-inspect <token.act|compact.txt>");
}
