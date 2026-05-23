//! High-level validation helpers for hot-path frames.

use core::convert::TryFrom;

use aegis_protocol_core::{
    CapabilityBinding, Error, MessageType, ReplayWindow, ResourceBudget, Result,
};

use crate::HotFrameHeader;

/// Context required to validate a hot-path frame before decoding its payload.
#[derive(Debug)]
pub struct HotFrameValidationContext<'a, const REPLAY_WORDS: usize> {
    /// Resource budget assigned to the frame.
    pub budget: ResourceBudget,
    /// Replay window for the stream.
    pub replay_window: &'a mut ReplayWindow<REPLAY_WORDS>,
    /// Optional capability binding to enforce.
    pub capability_binding: Option<CapabilityBinding>,
    /// Resolved message type for the negotiated type slot.
    pub message_type: MessageType,
    /// Absolute sequence number after expanding `seq_delta`.
    pub absolute_sequence: u64,
}

/// Validates hot-frame metadata before payload decoding.
pub fn validate_hot_frame<const REPLAY_WORDS: usize>(
    header: &HotFrameHeader,
    ctx: &mut HotFrameValidationContext<'_, REPLAY_WORDS>,
) -> Result<()> {
    let payload_len = usize::try_from(header.payload_len).map_err(|_| Error::ResourceExceeded)?;
    ctx.budget.ensure_frame_size(payload_len)?;
    ctx.replay_window.accept(ctx.absolute_sequence)?;

    if let Some(binding) = ctx.capability_binding {
        binding.ensure_allowed(ctx.message_type, header.capability_slot)?;
    }

    Ok(())
}
