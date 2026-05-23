# Aegis IDL MVP

Aegis IDL describes not only data shape, but also operational constraints. The MVP parser expects each block header on a single line.

```aegis
package billing.v1;

capability billing.capture_payment {
  scope merchant_id:u64;
  expires required;
  replay_window 10m;
}

state Authenticated {
  allow CapturePayment using billing.capture_payment;
}

message CapturePayment @type(0x2101) @max_size(1024) @cpu_budget(1ms) @memory_budget(4kb) @requires_capability(billing.capture_payment) @allowed_state(Authenticated) @idempotent(required) @security(hardened) {
  required u64 merchant_id = 1;
  required bytes idempotency_key = 2 size 32 @secret @no_log;
  optional string reference = 3 max 128 utf8 no_control_chars @safe_log;
}
```

## Message attributes

| Attribute | Meaning |
|---|---|
| `@type(...)` | Stable numeric message type |
| `@max_size(...)` | Maximum encoded message size |
| `@cpu_budget(...)` | Intended CPU budget token |
| `@memory_budget(...)` | Intended memory budget token |
| `@requires_capability(...)` | Capability required by this operation |
| `@allowed_state(...)` | Session state where this message may appear |
| `@idempotent(...)` | Idempotency requirement |
| `@security(...)` | Security profile |

## Field constraints

| Constraint | Meaning |
|---|---|
| `max N` | Maximum string/bytes length |
| `size N` | Exact bytes size |
| `max_items N` | Maximum repeated items |
| `item_max N` | Maximum repeated item size |
| `utf8` | String must be UTF-8 |
| `no_control_chars` | String rejects control characters |

## Field policies

Policies are annotations beginning with `@`, for example:

- `@safe_log`
- `@pii`
- `@secret`
- `@no_log`
- `@hash_log`
- `@constant_time_compare`


> MVP parser note: message attributes must currently appear on the same line as the `message` declaration.
