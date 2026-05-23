#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Parser, AST and validation helpers for the experimental Aegis IDL.

pub mod ast;
pub mod canonical;
pub mod error;
pub mod parser;
pub mod validation;

pub use ast::{
    Capability, Document, Field, FieldConstraints, FieldPresence, FieldType, Message,
    MessageContract, Scope, State, StateTransition,
};
pub use canonical::{canonical_document, fingerprint_hex, schema_fingerprint};
pub use error::IdlError;
pub use parser::parse_document;
pub use validation::validate_document;
