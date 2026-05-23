# Improvements in this ZIP

This revision strengthens the previous MVP in several practical ways:

- Added `aegis-protocol` umbrella crate for users who want one dependency.
- Added richer core primitives: frame flags, codec/compression policy, replay window, session state machine, capability bindings and operation identity IDs.
- Added wire-level helpers: message-envelope header, flow-control frame and hot-frame validation context.
- Added IDL support for capabilities, states, message contracts, canonical schema rendering and deterministic development fingerprints.
- Added semantic IDL validation for duplicate IDs/names, missing limits, invalid capabilities/states and unknown transition messages.
- Added codegen output for schema fingerprints, capability constants and field metadata constants.
- Added CLI commands for `check`, `fingerprint`, `generate --rust -o` and `inspect --hot`.
- Added extra docs: IDL MVP, security model, publishing guide, roadmap, changelog and contribution notes.

Still intentionally experimental:

- No custom cryptography implementation is included.
- The wire format is not stable before `1.0.0`.
- Generated code currently emits structs/constants, not full binary encoders/decoders.
- The IDL parser is intentionally line-oriented for the MVP.
