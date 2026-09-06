# BoneMesh Protocol Specification

This folder holds the protocol specification and its supporting artifacts:

- [`v2-behavior.md`](v2-behavior.md) — the v2 protocol as actually implemented
  (M2, **done**): a descriptive reference, warts documented, so the v3 delta is
  explicit.
- [`protocol.md`](protocol.md) / [`security.md`](security.md) — the v3
  specification (**normative as of 3.0.0**): framing/routing/delivery, and
  identity/handshake/threat-model respectively. The wire contract is frozen and
  corpus-pinned; a few session-lifecycle and tooling behaviors (rekey, idle
  timeout, retry/backoff outside the Java reference, simultaneous-dial
  resolution, the key-log debug hook) are **deferred** and labeled as such in
  each document.
- `corpus/` — shared test vectors and hostile-input corpora consumed by every
  implementation (**done**; enforced by all six ports and the conformance runner).
- `conformance/` — the language-agnostic conformance runner, in Go (**done**).

See [docs/PLAN.md](../docs/PLAN.md) §Phase 2.
