# Publishing to crates.io

Before publishing, confirm that the workspace repository URL points to the real
public repository.

## Local checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps
```

Package inspection:

```bash
cargo package -p aegis-protocol-core --list
cargo publish -p aegis-protocol-core --dry-run
```

## Publishing order

Publish in dependency order. For each package, run `--dry-run` first:

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

When using a workspace, each package is published separately with `-p`.
Internal dependencies use both `path` and `version`, so local development uses
the workspace path while crates.io resolves the published version.

## Recommended first release notes

Use conservative language for `0.1.0`:

```text
Experimental MVP. Wire format unstable. Not production-ready.
```

The safest first public crate is `aegis-protocol-core`. Publish the rest only
when you are comfortable committing to the names.

## Important crates.io rules

- Package versions are immutable.
- You cannot publish `0.1.0` twice.
- If a publish has a mistake, increment to `0.1.1` or `0.2.0`.
- Keep the wire format marked unstable until the protocol reaches `1.0.0`.
- Do not publish secrets, private schemas or generated credentials in examples.
