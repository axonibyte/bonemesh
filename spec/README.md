# BoneMesh Protocol Specification

This folder holds the protocol specification and its supporting artifacts:

- [`v2-behavior.md`](v2-behavior.md) — the v2 protocol as actually implemented
  (M2, **done**): a descriptive reference, warts documented, so the v3 delta is
  explicit.
- [`protocol.md`](protocol.md) / [`security.md`](security.md) — the v3
  specification (M3, **DRAFT for review**): framing/routing/delivery, and
  identity/handshake/threat-model respectively. Constants marked `[PIN]` freeze
  with the reference implementation + corpus.
- `corpus/` — shared test vectors and hostile-input corpora consumed by every
  implementation (M3, next unit)
- `conformance/` — the language-agnostic conformance runner, in Go (M3, next
  unit)

See [docs/PLAN.md](../docs/PLAN.md) §Phase 2.
