# BoneMesh #

**BoneMesh** is a point-to-point mesh network protocol with implementations in
multiple languages.

Traffic is authenticated and encrypted on every hop with NIST post-quantum
cryptography, and nodes route for one another. Six implementations — Java, Go,
Rust, PHP, Elixir, and JavaScript (Node.js) — all speak the same wire protocol,
so a mesh can be any mix of languages.

This repository is organized as a super-repo:

| Folder | Contents |
|---|---|
| `docs/` | Project-wide documentation: guides, plan, decisions, defect registry |
| `spec/` | The protocol specification, shared test corpora, and the conformance runner |
| `interop/` | The multiprotocol test suite that exercises implementations together |
| `java/` | The Java implementation (the original, and the v3 reference) |
| `go/`, `rust/`, `php/`, `elixir/`, `js/` | The other five full implementations |

### Documentation

- **[docs/user-guide.md](docs/user-guide.md)** — start here: concepts, standing
  up a mesh, running and embedding a node, the security model.
- **[docs/architecture.md](docs/architecture.md)** — how it is built: the
  protocol stack, cryptography, routing, and the cross-language testing regime.
- **[docs/testing.md](docs/testing.md)** — the testing guide: the tier map, the
  reaper tenants and how to run one, the interop battery, seed replay, the
  environment tunables, the gated long soak, and a key-log debugging walkthrough.
- **Per-language quickstarts** — build, test, and run the interop driver for one
  implementation: [go](go/README.md) · [rust](rust/README.md) ·
  [js](js/README.md) · [php](php/README.md) · [elixir](elixir/README.md) ·
  [java](java/README.md).
- **[spec/protocol.md](spec/protocol.md)** and
  **[spec/security.md](spec/security.md)** — the normative wire and security
  specifications.
- **[docs/PLAN.md](docs/PLAN.md)**, **[docs/decisions.md](docs/decisions.md)**,
  **[docs/defects.md](docs/defects.md)** — the roadmap and design/defect
  registries.

Copyright (c) 2019-2026 [Axonibyte Innovations, LLC](https://axonibyte.com).
Released under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

Authored and maintained primarily by [Caleb L. Power](https://calebpower.com).

This repository lives on [Bitbucket](https://bitbucket.org/axonibyte/bonemesh).
Other remote repository hosting providers (e.g. GitHub) serve as mirrors.
