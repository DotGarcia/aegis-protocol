# Aegis Protocol — Draft Specification

Aegis is a binary, schema-first and capability-first protocol. It is built
around the idea that a frame is not just bytes: it is an operation that must
be valid in a session state, authorized by a capability, bounded by resource
budgets and decoded against a compiled schema.

## Core invariants

1. No unvalidated bytes are exposed to application code.
2. Variable-sized fields must have explicit limits in the schema.
3. Unknown schemas, capabilities and state transitions are rejected by default.
4. Zero-copy views are exposed only after authentication, bounds checks and
   payload validation.
5. Compression is policy-driven, never global.
6. Hot-path frames reference negotiated slots instead of repeating metadata.
7. Replay protection is monotonic and windowed.
8. Logs are generated from schema policies, not ad-hoc application choices.

## Wire modes

- `transport-bound`: relies on a secure transport such as TLS 1.3 or QUIC.
- `message-envelope`: each message carries its own authentication envelope.

## Frame families

- **Control frame**: fixed 64-byte header for handshake, negotiation, errors and administration.
- **Hot frame**: compact varint header for frequently sent data operations.
- **Stream/flow frame**: small payloads for realtime flow control and backpressure.

## Payload layout

```text
Required Fixed Region
Optional Presence Bitmap
Optional Fixed Region
Variable Index
Variable Region
Optional Integrity/Canonical Trailer
```

## IDL safety requirements

- Every message must declare `@type(...)` and `@max_size(...)`.
- Every variable field must declare `max` or `size`.
- Every repeated field must declare `max_items`.
- Every repeated variable field must declare `item_max`.
- Every string field should declare `utf8`.
- Capabilities and allowed states must resolve to declarations in the document.

This workspace implements initial safe primitives and an MVP wire layout. It is
intentionally incomplete and unstable before version 1.0.
