# BoneMesh conformance runner (Go)

The language-agnostic conformance machinery for the BoneMesh v3 protocol
(decision #12: Go). It consumes the shared corpus in [`../corpus`](../corpus)
and will, once a v3 node exists (M4), also drive a running node over TCP and
check it against the same vectors.

## What it enforces today (the deterministic wire contract)

- **`canon/`** — certificate canonicalization (`../security.md` §11.1): the
  exact bytes the mesh root signs. Cross-language signature verification depends
  on every implementation producing these bytes identically.
- **`framing/`** — frame acceptance/rejection (`../protocol.md` §2): newline
  framing, hard size caps (defect D7), JSON validity, UTF-8.
- **`schema/`** — message schema validation (`../protocol.md` §4,
  `../security.md` §4) for handshake and transport frames.

Each package is driven by a corpus file and self-tested (breaking the code
under test makes a corpus case fail).

## Running

```
go test ./...          # runs every corpus-driven suite
```

This module is the `bonemesh-spec` reaper tenant; `reaper test` runs the same
thing in a pinned Go container.

## Not here yet

- **Handshake transcripts** and the crypto key-schedule constants — frozen at
  first interop (M4), when the Java reference and this runner exchange a real
  BMX handshake. Until then those constants are provisional (see `../security.md`).
- **`cmd/bmconf drive`** — driving a live node over TCP, pending that same node.
