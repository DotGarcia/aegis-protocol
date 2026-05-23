#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Core safe primitives for the experimental Aegis Protocol.
//!
//! Aegis is a schema-first and capability-first binary protocol for
//! high-performance machine-to-machine communication.
//!
//! This crate intentionally contains no networking or crypto implementation.
//! It provides the small shared types used by the other crates in the workspace.

pub mod budget;
pub mod capability;
pub mod codec;
pub mod error;
pub mod flags;
pub mod frame;
pub mod identity;
pub mod policy;
pub mod replay;
pub mod schema;
pub mod session;
pub mod slots;
pub mod varint;
pub mod view;

pub use budget::{BudgetClass, ResourceBudget};
pub use capability::{CapabilityBinding, CapabilityDecision};
pub use codec::{Codec, CompressionPolicy};
pub use error::{Error, Result};
pub use flags::FrameFlags;
pub use frame::{FrameKind, SecurityMode, TransportProfile};
pub use identity::{CausalId, OperationId, TraceId};
pub use policy::{FieldLogPolicy, SecurityProfile, Sensitivity};
pub use replay::ReplayWindow;
pub use schema::{MessageType, SchemaId};
pub use session::{OperationClass, SessionMachine, SessionState};
pub use slots::{BudgetSlot, CapabilitySlot, CodecSlot, StreamSlot, TypeSlot};
pub use view::{BytesView, StrView};

/// Current experimental protocol version.
pub const PROTOCOL_VERSION: u8 = 1;
