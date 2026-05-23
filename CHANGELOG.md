# Changelog

## 0.2.0 - ACT token support

- Added `aegis-protocol-token` crate.
- Added ACT binary and compact token representations.
- Added token signer/verifier traits.
- Added capability claims bound to schema ids and message types.
- Added `aegis token-inspect` CLI command.

## 0.1.0 - experimental MVP

- Added workspace with core, wire, IDL, codegen, CLI and umbrella crates.
- Added compact hot-frame headers and fixed control-frame headers.
- Added resource budgets, replay window, session state machine and policy bits.
- Added message-envelope metadata and flow-control frame helpers.
- Added IDL parsing for capabilities, states and messages.
- Added validation rules for message sizes, duplicate IDs and variable limits.
- Added CLI commands: `check`, `fingerprint`, `generate`, `inspect`.
