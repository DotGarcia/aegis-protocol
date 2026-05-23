# Security Policy

Aegis is experimental and should not be used in production yet.

## Design stance

The implementation follows these rules:

- reject malformed input by default
- validate sizes before slicing or exposing views
- require explicit limits for variable-length IDL fields
- keep zero-copy views behind validation
- avoid `unsafe` code in the MVP
- do not implement custom cryptography in this repository

## Reporting issues

Until a public security process exists, do not use Aegis for sensitive
production systems. If you fork this repository, establish your own private
security contact before deployment.
