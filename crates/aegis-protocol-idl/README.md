# aegis-protocol-idl

Minimal parser and AST for the experimental Aegis IDL.

This parser is intentionally small and conservative. It is meant as an MVP for
experimentation, not as the final grammar implementation.

Currently supports:

- `package`
- `capability` blocks with scope, expiry and replay window
- `state` blocks with allowed message transitions
- `message` blocks with `@type(...)` and `@max_size(...)`
- required/optional/repeated fields
- basic field constraints: `max`, `size`, `max_items`, `item_max`
- field annotations such as `@secret`, `@safe_log` and `@no_log`

The parser validates duplicate IDs/names and requires explicit limits for
variable-length fields.
