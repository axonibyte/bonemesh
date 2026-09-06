# BoneMesh Protocol Specification

This folder holds the protocol specification and its supporting artifacts:

- [`v2-behavior.md`](v2-behavior.md) — the v2 protocol as actually implemented
  (M2, **done**): a descriptive reference, warts documented, so the v3 delta is
  explicit.
- [`protocol.md`](protocol.md) / [`security.md`](security.md) — the v3
  specification (**normative as of 3.1.0**): framing/routing/delivery, and
  identity/handshake/threat-model respectively. The wire contract is frozen and
  corpus-pinned. The session-lifecycle and tooling behaviors 3.0.0 had deferred
  (simultaneous-dial resolution, retry/backoff, probe-timeout liveness, idle
  teardown, session rekey, ack/NAK emission, and the key-log hook) are all
  delivered as of 3.1.0 across every implementation and exercised by interop
  tier 10.
- `corpus/` — shared test vectors and hostile-input corpora consumed by every
  implementation (**done**; enforced by all six ports and the conformance runner).
- `conformance/` — the language-agnostic conformance runner, in Go (**done**).

See [docs/PLAN.md](../docs/PLAN.md) §Phase 2.
