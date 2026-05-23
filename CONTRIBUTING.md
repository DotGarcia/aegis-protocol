# Contributing

This is an experimental protocol workspace. Please keep contributions focused on
small, testable pieces.

Recommended local checks:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Guidelines:

- Avoid `unsafe` unless isolated, justified and heavily tested.
- Validate lengths before slicing.
- Keep variable-length fields explicitly bounded.
- Add tests for malformed input, not only happy paths.
- Keep wire-format changes documented in `docs/SPEC_DRAFT.md`.
