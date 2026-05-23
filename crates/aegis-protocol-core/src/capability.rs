//! Capability binding primitives.

use crate::{CapabilitySlot, Error, MessageType, Result};

/// Capability required for a specific message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityBinding {
    /// Message type this binding protects.
    pub message_type: MessageType,
    /// Slot negotiated for the required capability.
    pub capability_slot: CapabilitySlot,
}

impl CapabilityBinding {
    /// Creates a new binding.
    pub const fn new(message_type: MessageType, capability_slot: CapabilitySlot) -> Self {
        Self {
            message_type,
            capability_slot,
        }
    }

    /// Ensures a frame uses the expected capability slot for this message.
    pub fn ensure_allowed(
        self,
        message_type: MessageType,
        capability_slot: CapabilitySlot,
    ) -> Result<()> {
        if self.message_type == message_type && self.capability_slot == capability_slot {
            Ok(())
        } else {
            Err(Error::CapabilityDenied)
        }
    }
}

/// Scope check result for a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityDecision {
    /// Capability is accepted.
    Allow,
    /// Capability exists but does not cover this operation.
    Deny,
}

impl CapabilityDecision {
    /// Converts the decision to a result.
    pub fn into_result(self) -> Result<()> {
        match self {
            Self::Allow => Ok(()),
            Self::Deny => Err(Error::CapabilityDenied),
        }
    }
}
