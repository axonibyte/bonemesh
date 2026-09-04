# BoneMesh #

**BoneMesh** is a point-to-point mesh network protocol with implementations in
multiple languages.

This repository is organized as a super-repo:

| Folder | Contents |
|---|---|
| `docs/` | Project-wide documentation: plan, decisions, defect registry, security model |
| `spec/` | The protocol specification, shared test corpora, and the conformance runner |
| `interop/` | The multiprotocol test suite that exercises implementations together |
| `java/` | The Java implementation (the original, and the v3 reference) |

Implementations in Go, Rust, PHP, Elixir, and JavaScript (Node) are planned;
each will live in its own top-level folder. See [docs/PLAN.md](docs/PLAN.md)
for the roadmap.

Copyright (c) 2019-2026 [Axonibyte Innovations, LLC](https://axonibyte.com).
Released under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

Authored and maintained primarily by [Caleb L. Power](https://calebpower.com).

This repository lives on [Bitbucket](https://bitbucket.org/axonibyte/bonemesh).
Other remote repository hosting providers (e.g. GitHub) serve as mirrors.
