#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Umbrella crate for the experimental Aegis Protocol.
//!
//! Aegis is a schema-first and capability-first binary protocol for secure,
//! high-performance machine-to-machine communication.

pub use aegis_protocol_core as core;

#[cfg(feature = "wire")]
pub use aegis_protocol_wire as wire;

#[cfg(feature = "token")]
pub use aegis_protocol_token as token;

#[cfg(feature = "idl")]
pub use aegis_protocol_idl as idl;

#[cfg(feature = "codegen")]
pub use aegis_protocol_codegen as codegen;

#[cfg(feature = "token")]
pub use aegis_protocol_token::{
    AegisClaims, AegisToken, CapabilityClaim, CapabilityFlags, TokenAlgorithm, TokenFlags,
    TokenHeader, TokenProfile, TokenSigner, TokenVerifier, ValidationContext, ACT_COMPACT_PREFIX,
    ACT_MAGIC, ACT_VERSION,
};

pub use aegis_protocol_core::{
    BudgetClass, BudgetSlot, BytesView, CapabilityBinding, CapabilityDecision, CapabilitySlot,
    CausalId, Codec, CodecSlot, CompressionPolicy, Error, FieldLogPolicy, FrameFlags, FrameKind,
    MessageType, OperationClass, OperationId, ReplayWindow, ResourceBudget, Result, SchemaId,
    SecurityMode, SecurityProfile, Sensitivity, SessionMachine, SessionState, StrView, StreamSlot,
    TraceId, TransportProfile, TypeSlot, PROTOCOL_VERSION,
};
