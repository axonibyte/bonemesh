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
| `transcripts/handshake-agreement.json` | The X25519 hybrid agreement + schedule → transport keys. | **active** (Java + Go). See `transcripts/README.md` for deferred ML-KEM/ML-DSA items. |

Adversarial framing-level inputs a node must reject without crashing (oversize,
injection, truncation, invalid UTF-8, non-object) live in `framing.json`, and
adversarial *semantic* inputs (bad versions, malformed ids, out-of-range fields)
live in `messages.json` as their `invalid` cases — rather than a separate
hostile file, each hostile input sits with the layer that must reject it.

The `transcripts/` vectors freeze the handshake's cryptographic core across
languages (Java + Go); `transcripts/README.md` records exactly what is frozen
and which items (ML-KEM cross-decapsulation, ML-DSA signatures, the byte-exact
full transcript) are deferred and why.
