# Roadmap

## Phase 1 — MVP hardening

- Expand IDL grammar beyond the current line-oriented parser.
- Add canonical schema normalization and cryptographic schema fingerprints.
- Add generated encoders/decoders for fixed and variable payload regions.
- Add fuzz targets for varints, headers, layout validation and IDL parsing.

## Phase 2 — Session layer

- Add typed handshake messages.
- Negotiate type/capability/budget/codec slots.
- Bind transcript hashes to frames.
- Add key rotation hooks for QUIC/TLS and message-envelope modes.

## Phase 3 — Production profiles

- Add realtime stream profile with backpressure.
- Add bulk columnar blocks.
- Add audit hash chains.
- Add idempotency/deduplication helpers.
- Add full crates.io release automation with trusted publishing.
