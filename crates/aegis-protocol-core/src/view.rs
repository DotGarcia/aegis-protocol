//! Validated zero-copy views.

use crate::{Error, Result};

/// Borrowed byte view.
///
/// This type should only be constructed after authentication and payload
/// validation have completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BytesView<'a> {
    inner: &'a [u8],
}

impl<'a> BytesView<'a> {
    /// Creates a new validated byte view.
    pub const fn new_validated(inner: &'a [u8]) -> Self {
        Self { inner }
    }

    /// Creates a byte view after checking a maximum length.
    pub fn try_from_bytes_with_limit(inner: &'a [u8], max_len: usize) -> Result<Self> {
        if inner.len() > max_len {
            return Err(Error::ResourceExceeded);
        }
        Ok(Self { inner })
    }

    /// Returns the underlying bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.inner
    }

    /// Returns the byte length of this view.
    pub const fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if this view is empty.
    pub const fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Borrowed UTF-8 string view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StrView<'a> {
    inner: &'a str,
}

impl<'a> StrView<'a> {
    /// Validates UTF-8 and creates a string view.
    pub fn try_from_bytes(bytes: &'a [u8]) -> Result<Self> {
        match core::str::from_utf8(bytes) {
            Ok(inner) => Ok(Self { inner }),
            Err(_) => Err(Error::InvalidUtf8),
        }
    }

    /// Validates UTF-8, maximum byte length and optional control-character policy.
    pub fn try_from_bytes_with_policy(
        bytes: &'a [u8],
        max_len: usize,
        no_control_chars: bool,
    ) -> Result<Self> {
        if bytes.len() > max_len {
            return Err(Error::ResourceExceeded);
        }
        let inner = core::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
        if no_control_chars && inner.chars().any(|ch| ch.is_control()) {
            return Err(Error::PolicyViolation);
        }
        Ok(Self { inner })
    }

    /// Creates a new view from a string that is already valid UTF-8.
    pub const fn new_validated(inner: &'a str) -> Self {
        Self { inner }
    }

    /// Returns the underlying string.
    pub const fn as_str(&self) -> &'a str {
        self.inner
    }

    /// Returns the byte length of this string view.
    pub const fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if this view is empty.
    pub const fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}
