# aegis-protocol-core

Core safe primitives for the experimental Aegis secure binary protocol.

Includes:

- protocol errors
- frame kinds and transport/security modes
- resource budgets
- policy bits and redaction decisions
- compression policy helpers
- session slot newtypes
- schema and message identifiers
- replay protection window
- minimal typed session state machine
- capability binding helpers
- operation/trace/causal identifiers
- varint encoding/decoding
- validated zero-copy byte/string views

Status: experimental. The wire format is unstable before `1.0.0`.
