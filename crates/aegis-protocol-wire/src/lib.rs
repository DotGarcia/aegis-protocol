#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Wire-format framing and payload validation for Aegis.

pub mod control;
pub mod envelope;
pub mod flow;
pub mod hot;
pub mod layout;
pub mod stream;
pub mod validator;

pub use control::{ControlFrameHeader, CONTROL_HEADER_LEN, CONTROL_MAGIC};
pub use envelope::{
    MessageEnvelopeHeader, ENVELOPE_HEADER_LEN, ENVELOPE_NONCE_LEN, ENVELOPE_TAG_LEN,
};
pub use flow::{FlowControlFrame, FlowKind};
pub use hot::{HotFrameHeader, MAX_HOT_HEADER_LEN};
pub use layout::{
    optional_field_present, read_i64_le, read_u16_le, read_u32_le, read_u64_le,
    read_variable_index_entry, split_payload, validate_variable_index_table, variable_str_view,
    variable_view, LayoutSpec, PayloadSections, VariableIndexEntry, VARIABLE_INDEX_ENTRY_LEN,
};
pub use stream::{StreamSignal, WindowUpdate};
pub use validator::{validate_hot_frame, HotFrameValidationContext};
