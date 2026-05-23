# ACT — Aegis Capability Token

ACT is the Aegis counterpart to JWT.

JWT is a JSON-based token format. ACT is a deterministic binary capability token
built for the Aegis protocol. It is designed to bind authorization to Aegis
schemas, message types, resource budgets and security profiles.

## Design goals

- no JSON in the token body
- deterministic binary encoding
- explicit schema fingerprint binding
- explicit capability claims
- optional compact text representation for headers and config files
- no built-in crypto implementation
- safe validation before a token becomes an active capability

## Formats

ACT supports two serializations of the same token model.

### Binary ACT

```text
ACT1 || version || len(header) || len(claims) || len(signature) || header || claims || signature
```

### Compact ACT

```text
act1.<base64url(header)>.<base64url(claims)>.<base64url(signature)>
```

The compact form is convenient for HTTP headers, configuration, terminals and
copy/paste workflows. The header and claims are still binary, not JSON.

## Signing input

Signatures cover a domain-separated canonical binary input:

```text
"Aegis-ACT-v1\\0" || len(header) || header || len(claims) || claims
```

This crate does not implement Ed25519, HMAC, ECDSA or post-quantum algorithms.
It exposes `TokenSigner` and `TokenVerifier` traits so applications can plug in
audited crypto libraries.

## Claims

An ACT carries:

- issuer
- subject
- audience
- issued-at timestamp
- not-before timestamp
- expiration timestamp
- token id for replay/dedup tracking
- schema fingerprint
- maximum budget class
- security profile
- one or more capability claims

A capability claim carries:

- stable capability id
- diagnostic capability name
- binary scope blob
- optional capability-specific expiration
- capability flags
- explicit message-type allow-list

## Validation

A verifier should check, in order:

1. decode token structure
2. reject `Unsecured` unless explicitly allowed for tests/examples
3. verify signature using the selected key id and algorithm
4. validate expiration and not-before timestamps
5. validate audience
6. validate schema fingerprint
7. validate required capability id
8. validate required message type
9. bind the accepted capability to the Aegis session slot

## Why this is better than a JWT clone

ACT is not merely a signed set of claims. It is designed around Aegis concepts:

- schema id instead of arbitrary JSON payloads
- capabilities instead of generic roles
- message-type allow-lists instead of broad permissions
- resource budgets instead of implicit trust
- binary scope blobs instead of stringly-typed JSON objects
- optional compact representation without making JSON the source of truth

## Current crate

The implementation lives in `crates/aegis-protocol-token`.

CLI inspection:

```bash
cargo run -p aegis-protocol-cli -- token-inspect examples/capability_token.act.txt
```

Real signing requires implementing `TokenSigner` and `TokenVerifier` with an
audited cryptography crate.
