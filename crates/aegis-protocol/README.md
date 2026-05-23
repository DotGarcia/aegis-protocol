# aegis-protocol

Umbrella crate for the experimental Aegis secure binary protocol.

This crate re-exports the lower-level crates:

- `aegis_protocol_core`
- `aegis_protocol_wire` behind the `wire` feature
- `aegis_protocol_token` behind the `token` feature
- `aegis_protocol_idl` behind the `idl` feature
- `aegis_protocol_codegen` behind the `codegen` feature

Enable the `token` feature to use `aegis-protocol-token`, which provides ACT:
Aegis Capability Tokens. ACT is a deterministic binary token format for
capability-bearing credentials, with a compact text representation for
transport.

## Status

Experimental. Do not use in production yet. The wire format is unstable before `1.0.0`.

## License

MIT OR Apache-2.0
