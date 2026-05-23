# Security Model

Aegis treats every frame as a proposed operation, not as inert data.

A frame is acceptable only when all of these checks pass:

```text
valid framing
AND version accepted
AND sequence/replay accepted
AND schema/type slot accepted
AND session state allows the operation
AND capability allows the operation
AND resource budget allows the operation
AND payload layout is valid
AND variable offsets are in range
AND field policies are satisfied
```

## Zero-copy boundary

Aegis views such as `BytesView` and `StrView` are designed to be created only
after authentication, budget checks and payload validation. The MVP crates do
not implement cryptography; deployments should bind Aegis to TLS 1.3, QUIC or a
message-envelope profile.

## Compression

Compression is contextual. It should be disabled when secret data and
user-controlled input share the same compression context unless the deployment
uses explicit padding or another side-channel mitigation.

## Replay protection

The core crate contains a fixed-size `ReplayWindow` for monotonic sequence
numbers. It rejects duplicate and stale sequence values inside the configured
window.

## Logging

IDL field policies should drive logging decisions. Secret fields should use
`@no_log`; PII should be redacted or hashed according to your deployment rules.
