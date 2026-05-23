//! Typed session state primitives.

use crate::{Error, Result};

/// Built-in session states for the MVP state machine.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// No authentication has happened yet.
    Anonymous = 0,
    /// Handshake is in progress.
    Handshaking = 1,
    /// Peer is authenticated and can open streams or send operations.
    Authenticated = 2,
    /// A typed stream is open.
    StreamOpen = 3,
    /// Connection is closing or closed.
    Closed = 4,
}

/// High-level operation class used for state transition checks.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationClass {
    /// Client hello or equivalent initial negotiation.
    ClientHello = 0,
    /// Authentication proof.
    AuthProof = 1,
    /// Application request/response operation.
    Application = 2,
    /// Open a new stream.
    OpenStream = 3,
    /// Data on an already open stream.
    StreamData = 4,
    /// Close a stream or connection.
    Close = 5,
    /// Heartbeat or keepalive.
    Heartbeat = 6,
}

/// Minimal allocation-free typed session machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionMachine {
    state: SessionState,
}

impl SessionMachine {
    /// Creates a new session machine in the anonymous state.
    pub const fn new() -> Self {
        Self {
            state: SessionState::Anonymous,
        }
    }

    /// Creates a machine at a specific state.
    pub const fn at(state: SessionState) -> Self {
        Self { state }
    }

    /// Returns the current state.
    pub const fn state(self) -> SessionState {
        self.state
    }

    /// Checks whether an operation is valid in the current state.
    pub const fn allows(self, operation: OperationClass) -> bool {
        matches!(
            (self.state, operation),
            (SessionState::Anonymous, OperationClass::ClientHello)
                | (SessionState::Handshaking, OperationClass::AuthProof)
                | (SessionState::Handshaking, OperationClass::Close)
                | (SessionState::Authenticated, OperationClass::Application)
                | (SessionState::Authenticated, OperationClass::OpenStream)
                | (SessionState::Authenticated, OperationClass::Heartbeat)
                | (SessionState::Authenticated, OperationClass::Close)
                | (SessionState::StreamOpen, OperationClass::StreamData)
                | (SessionState::StreamOpen, OperationClass::Heartbeat)
                | (SessionState::StreamOpen, OperationClass::Close)
        )
    }

    /// Applies an operation and updates the session state.
    pub fn apply(&mut self, operation: OperationClass) -> Result<SessionState> {
        if !self.allows(operation) {
            return Err(Error::StateDenied);
        }

        self.state = match (self.state, operation) {
            (SessionState::Anonymous, OperationClass::ClientHello) => SessionState::Handshaking,
            (SessionState::Handshaking, OperationClass::AuthProof) => SessionState::Authenticated,
            (SessionState::Authenticated, OperationClass::OpenStream) => SessionState::StreamOpen,
            (SessionState::StreamOpen, OperationClass::Close) => SessionState::Authenticated,
            (_, OperationClass::Close) => SessionState::Closed,
            (state, _) => state,
        };
        Ok(self.state)
    }
}

impl Default for SessionMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_app_before_authentication() {
        let mut machine = SessionMachine::new();
        assert_eq!(
            machine.apply(OperationClass::Application),
            Err(Error::StateDenied)
        );
        assert!(machine.apply(OperationClass::ClientHello).is_ok());
        assert!(machine.apply(OperationClass::AuthProof).is_ok());
        assert!(machine.apply(OperationClass::Application).is_ok());
    }
}
