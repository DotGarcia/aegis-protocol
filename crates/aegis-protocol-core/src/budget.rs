//! Resource budgets used by decoders and validators.

use crate::{Error, Result};

/// Named budget classes negotiated during a session.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetClass {
    /// Very small control-plane or heartbeat messages.
    Tiny = 0,
    /// Normal API-sized messages.
    Normal = 1,
    /// Larger streaming or bulk chunks.
    Bulk = 2,
    /// Privileged or operator-controlled budget.
    Privileged = 3,
}

/// Limits enforced before application code receives decoded data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceBudget {
    /// Maximum encoded frame length in bytes.
    pub max_frame_size: usize,
    /// Maximum decoded payload bytes after optional decompression.
    pub max_decoded_size: usize,
    /// Maximum single string size in bytes.
    pub max_string_size: usize,
    /// Maximum single bytes field size in bytes.
    pub max_bytes_size: usize,
    /// Maximum bytes consumed by all variable fields in a payload.
    pub max_variable_bytes: usize,
    /// Maximum number of array items.
    pub max_array_items: usize,
    /// Maximum nested structural depth.
    pub max_depth: usize,
    /// Maximum fields in one decoded message.
    pub max_fields: usize,
    /// Maximum simultaneously open streams.
    pub max_streams: usize,
    /// Maximum allowed decompression ratio.
    pub max_compression_ratio: usize,
}

impl ResourceBudget {
    /// Tiny default budget.
    pub const fn tiny() -> Self {
        Self {
            max_frame_size: 4 * 1024,
            max_decoded_size: 4 * 1024,
            max_string_size: 1024,
            max_bytes_size: 4 * 1024,
            max_variable_bytes: 4 * 1024,
            max_array_items: 128,
            max_depth: 4,
            max_fields: 64,
            max_streams: 16,
            max_compression_ratio: 8,
        }
    }

    /// Normal default budget.
    pub const fn normal() -> Self {
        Self {
            max_frame_size: 1024 * 1024,
            max_decoded_size: 4 * 1024 * 1024,
            max_string_size: 256 * 1024,
            max_bytes_size: 1024 * 1024,
            max_variable_bytes: 2 * 1024 * 1024,
            max_array_items: 1_000_000,
            max_depth: 32,
            max_fields: 512,
            max_streams: 128,
            max_compression_ratio: 16,
        }
    }

    /// Bulk default budget.
    pub const fn bulk() -> Self {
        Self {
            max_frame_size: 64 * 1024 * 1024,
            max_decoded_size: 256 * 1024 * 1024,
            max_string_size: 1024 * 1024,
            max_bytes_size: 64 * 1024 * 1024,
            max_variable_bytes: 128 * 1024 * 1024,
            max_array_items: 64_000_000,
            max_depth: 32,
            max_fields: 4096,
            max_streams: 1024,
            max_compression_ratio: 32,
        }
    }

    /// Returns the recommended budget for a class.
    pub const fn for_class(class: BudgetClass) -> Self {
        match class {
            BudgetClass::Tiny => Self::tiny(),
            BudgetClass::Normal => Self::normal(),
            BudgetClass::Bulk => Self::bulk(),
            BudgetClass::Privileged => Self::bulk(),
        }
    }

    /// Ensures a frame length is inside this budget.
    pub fn ensure_frame_size(&self, len: usize) -> Result<()> {
        if len <= self.max_frame_size {
            Ok(())
        } else {
            Err(Error::ResourceExceeded)
        }
    }

    /// Ensures a decoded length is inside this budget.
    pub fn ensure_decoded_size(&self, len: usize) -> Result<()> {
        if len <= self.max_decoded_size {
            Ok(())
        } else {
            Err(Error::ResourceExceeded)
        }
    }

    /// Ensures a string length is inside this budget.
    pub fn ensure_string_size(&self, len: usize) -> Result<()> {
        if len <= self.max_string_size {
            Ok(())
        } else {
            Err(Error::ResourceExceeded)
        }
    }

    /// Ensures a bytes field length is inside this budget.
    pub fn ensure_bytes_size(&self, len: usize) -> Result<()> {
        if len <= self.max_bytes_size {
            Ok(())
        } else {
            Err(Error::ResourceExceeded)
        }
    }

    /// Ensures a variable-region length is inside this budget.
    pub fn ensure_variable_bytes(&self, len: usize) -> Result<()> {
        if len <= self.max_variable_bytes {
            Ok(())
        } else {
            Err(Error::ResourceExceeded)
        }
    }

    /// Ensures an array item count is inside this budget.
    pub fn ensure_array_items(&self, count: usize) -> Result<()> {
        if count <= self.max_array_items {
            Ok(())
        } else {
            Err(Error::ResourceExceeded)
        }
    }

    /// Ensures a nesting depth is inside this budget.
    pub fn ensure_depth(&self, depth: usize) -> Result<()> {
        if depth <= self.max_depth {
            Ok(())
        } else {
            Err(Error::ResourceExceeded)
        }
    }

    /// Ensures a field count is inside this budget.
    pub fn ensure_fields(&self, fields: usize) -> Result<()> {
        if fields <= self.max_fields {
            Ok(())
        } else {
            Err(Error::ResourceExceeded)
        }
    }

    /// Ensures decompression output is inside this budget and ratio is bounded.
    pub fn ensure_compression_ratio(
        &self,
        compressed_len: usize,
        decoded_len: usize,
    ) -> Result<()> {
        self.ensure_decoded_size(decoded_len)?;
        if compressed_len == 0 {
            return Err(Error::MalformedFrame);
        }
        if decoded_len <= compressed_len.saturating_mul(self.max_compression_ratio) {
            Ok(())
        } else {
            Err(Error::ResourceExceeded)
        }
    }
}
