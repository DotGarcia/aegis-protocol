# aegis-protocol-wire

Wire-format framing and payload validation for the experimental Aegis protocol.

Includes:

- compact hot-path frame headers
- 64-byte control frame header
- message-envelope metadata for brokered/offline delivery
- flow-control frame helpers
- fixed/variable payload layout splitting
- variable index bounds validation
- hot-frame metadata validation against budget, replay and capability binding

Status: experimental. The wire format is unstable before `1.0.0`.
