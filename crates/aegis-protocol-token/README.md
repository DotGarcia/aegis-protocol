# Aegis Protocol Token

Experimental Aegis Capability Token primitives.

An **Aegis Capability Token** (**ACT**) is the Aegis analogue to JWT: a portable
token that carries issuer, subject, audience, schema fingerprint and capability
claims.

Unlike JWT, ACT claims are encoded as deterministic binary data, not JSON.

## Supported representations

Binary:

```text
ACT1 || version || len(header) || len(claims) || len(signature) || header || claims || signature
```

Compact text:

```text
act1.<base64url(header)>.<base64url(claims)>.<base64url(signature)>
```

## Crypto model

This crate does **not** implement cryptographic signing algorithms. It defines
`TokenSigner` and `TokenVerifier` traits so applications can plug in audited
crypto libraries such as Ed25519, HMAC-SHA256 or ECDSA P-256.

The `Unsecured` algorithm exists only for tests and examples and must be rejected
by production validation policy.

## Status

Experimental. Do not use in production yet.

The token format is unstable before version 1.0.

## License

MIT OR Apache-2.0
