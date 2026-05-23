//! IDL parser errors.

use std::fmt;

/// Error returned by the minimal IDL parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdlError {
    line: usize,
    message: String,
}

impl IdlError {
    /// Creates a new parser error.
    pub fn new(line: usize, message: impl Into<String>) -> Self {
        Self {
            line,
            message: message.into(),
        }
    }

    /// Returns the 1-based line number.
    pub fn line(&self) -> usize {
        self.line
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for IdlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for IdlError {}
