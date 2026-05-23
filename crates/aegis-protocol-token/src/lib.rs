#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Aegis Capability Token primitives.
//!
//! ACT is the Aegis analogue to JWT: a compact token carrying issuer, subject,
//! audience, schema binding and capability claims. Unlike JWT, ACT is encoded
//! as deterministic binary data and is designed to bind directly to Aegis
//! schemas, operations and capabilities.
//!
//! This crate intentionally does not implement cryptographic algorithms. Use
//! the [`TokenSigner`] and [`TokenVerifier`] traits with an audited crypto crate.

#[cfg(not(feature = "alloc"))]
compile_error!("aegis-protocol-token requires the `alloc` feature; `std` enables it by default");

extern crate alloc;

pub mod algorithm;
pub mod claims;
pub mod codec;
pub mod compact;
pub mod error;
pub mod flags;
pub mod token;

pub use algorithm::{TokenAlgorithm, TokenProfile};
pub use claims::{AegisClaims, CapabilityClaim, TokenHeader, ValidationContext};
pub use compact::{base64url_decode, base64url_encode};
pub use error::{Result, TokenError};
pub use flags::{CapabilityFlags, TokenFlags};
pub use token::{
    signing_input_for_parts, AegisToken, TokenSigner, TokenVerifier, ACT_COMPACT_PREFIX, ACT_MAGIC,
    ACT_SIGNING_DOMAIN, ACT_VERSION,
};
