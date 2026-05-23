# Aegis Protocol ⚡🛡️

Aegis is an **experimental secure binary protocol** for high-performance
machine-to-machine communication.

It is designed around these principles:

- schema-first contracts
- capability-aware operations
- typed sessions
- strict resource budgets
- validated zero-copy views
- compact hot-path frames
- optional message envelopes
- safe-by-default Rust implementation

> Status: experimental. Do **not** use this crate family in production yet.
> The wire format is unstable before `1.0.0`.

## What improved in this package

This version includes a more complete MVP surface:

- umbrella crate: `aegis-protocol`
- stronger core primitives: codec policy, frame flags, replay window, richer budgets
- wire helpers: hot-frame budget validation, bitmap checks, string/bytes views, stream flow-control payload
- IDL improvements: capabilities, states, message contracts, validation and schema fingerprints
- codegen improvements: schema fingerprint constants, capability constants and field constraint constants
- CLI improvements: `check`, `fingerprint`, `generate --rust -o`, and `inspect --hot`
- extra docs for IDL, security model and publishing

## Workspace

| Crate | Purpose |
|---|---|
| `aegis-protocol` | Umbrella crate that re-exports the family |
| `aegis-protocol-core` | Core protocol types, errors, budgets, replay window, policies, varints and safe views |
| `aegis-protocol-wire` | Hot/control frame headers, stream helpers and payload layout validation |
| `aegis-protocol-idl` | Aegis IDL parser, AST, semantic validation and fingerprints |
| `aegis-protocol-codegen` | Rust code generation from Aegis IDL |
| `aegis-protocol-cli` | Small `aegis` command-line tool |

## Quick start

```bash
cargo test --workspace --all-features
cargo run -p aegis-protocol-cli -- check examples/capture_payment.aegis
cargo run -p aegis-protocol-cli -- fingerprint examples/capture_payment.aegis
cargo run -p aegis-protocol-cli -- generate examples/capture_payment.aegis --rust -o generated.rs
```

## Publishing order

Publish dependency crates first, then the umbrella crate and CLI:

```bash
cargo publish -p aegis-protocol-core --dry-run
cargo publish -p aegis-protocol-core

cargo publish -p aegis-protocol-wire --dry-run
cargo publish -p aegis-protocol-wire

cargo publish -p aegis-protocol-idl --dry-run
cargo publish -p aegis-protocol-idl

cargo publish -p aegis-protocol-codegen --dry-run
cargo publish -p aegis-protocol-codegen

cargo publish -p aegis-protocol --dry-run
cargo publish -p aegis-protocol

cargo publish -p aegis-protocol-cli --dry-run
cargo publish -p aegis-protocol-cli
```

Before publishing, confirm the repository URL and that the names are available
on crates.io.

## License

Licensed under either of:

- MIT license
- Apache License, Version 2.0

at your option.
