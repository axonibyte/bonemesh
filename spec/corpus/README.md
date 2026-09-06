# BoneMesh conformance corpus

Language-agnostic test data. Every BoneMesh implementation is expected to
consume these vectors and behave as each file specifies; the Go conformance
runner in [`../conformance`](../conformance) does so as the first consumer.

Each file is JSON so any language can load it. Vectors state what they prove and
what a conforming implementation must do.

| File | Proves | Status |
|---|---|---|
| `canon.json` | Certificate canonicalization (`security.md` §11.1) produces exact bytes — the precondition for cross-language signature verification. | **active** |
| `framing.json` | Frame acceptance/rejection: size caps, newline framing, JSON validity, UTF-8 (`protocol.md` §2, D7). | **active** |
| `messages.json` | Message schema validation for handshake and transport frames (`protocol.md` §4, `security.md` §4). | **active** |
| `transcripts/keyschedule.json` | The BMX key schedule — transcript hashes, chaining keys, ciphertexts, transport keys. | **active** (Java + Go) |
| `transcripts/handshake-agreement.json` | The X25519 hybrid agreement + schedule → transport keys. | **active** (Java + Go). |
| `transcripts/pqc-interop.json` | ML-KEM-768 cross-decapsulation and ML-DSA-65 signature verification. | **active** (proven across all six). |

Adversarial framing-level inputs a node must reject without crashing (oversize,
injection, truncation, invalid UTF-8, non-object) live in `framing.json`, and
adversarial *semantic* inputs (bad versions, malformed ids, out-of-range fields)
live in `messages.json` as their `invalid` cases — rather than a separate
hostile file, each hostile input sits with the layer that must reject it.

The `lenient-*` cases pin strict RFC 8259 parsing: unquoted keys (`{a:1}`),
single-quoted strings, trailing commas, leading-zero numbers, and `NaN` are
inputs a lenient JSON library accepts but a conforming frame reader must reject
as `invalid-json`. Java's classifier previously used org.json's lenient tokener
and accepted them; as of 3.1.0 it validates the object in org.json strict mode
(keeping the lenient pass only to preserve the `trailing-data` verdict), so all
six implementations now agree byte-for-byte on every case — enforced per
language and cross-checked against the Go reference by `interop/check-framing*`.

The `transcripts/` vectors freeze the handshake's cryptographic core:
the key agreement and schedule (Java + Go) and the post-quantum layer —
ML-KEM cross-decapsulation and ML-DSA signatures (`pqc-interop.json`) — proven
across all six. `transcripts/README.md` records exactly what is frozen; the only
remaining optional item is a byte-exact full-transcript vector for offline
conformance, unnecessary now that the live cross-language handshake is proven
end to end.
