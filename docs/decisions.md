# Decisions

Lightweight decision registry. One entry per settled decision; newest at the
bottom. Revisiting a decision gets a new entry that names the one it replaces.

| # | Date | Decision | Rationale |
|---|---|---|---|
| 1 | 2026-09-04 | The protocol specification is the product; implementations conform to it. No port begins before the v3 spec exists. | Six implementations of one ambiguous codebase would be six projects; a spec plus conformance vectors makes them one. |
| 2 | 2026-09-04 | Super-repo layout: `docs/`, `spec/`, `interop/`, one folder per language, no `bonemesh-` folder prefix. | Spec, corpora, and implementations move in lockstep; cross-repo interop testing is miserable. Repo name already carries the brand. |
| 3 | 2026-09-04 | Wire format is JSON everywhere; no binary serialization. | Readability of the objects in flight is a design value of the project. |
| 4 | 2026-09-04 | v3 security: Noise-framework-style authenticated handshake, hybrid X25519 + ML-KEM (FIPS 203), ML-DSA (FIPS 204) node identities. NIST PQC where possible. | Owner requirement for NIST PQC; hybrid rather than PQ-only so a flaw in young ML-KEM implementations doesn't drop the mesh below classical security. Supersedes the dev-branch Kyber prototype (round-3 draft, unauthenticated key distribution). |
| 5 | 2026-09-04 | "Readable in flight" under encryption means: plain JSON at the protocol layer, plus a spec'd session-key logging hook and a bundled inspector tool for development. | Keeps the readability guarantee without a plaintext production mode. |
| 6 | 2026-09-04 | PHP is a full routing node, same peer status as the other implementations. | Owner call; no special-casing in the spec. |
| 7 | 2026-09-04 | Testing follows reaper's testing-methodology.md: per-language reaper tenants own tiers 1-4; a root interop tenant owns tiers 5-9, written once, language-agnostic. | Verified reaper resolves the synced tree from the manifest's directory, so subdirectory tenants need no reaper changes. Black-box harnesses over TCP don't care about implementation language. |
| 8 | 2026-09-04 | Baseline is the former `dev` branch (d807d83); `main` fast-forwarded to it. | dev was strictly ahead (Java 17, NPE fix #3, crypto prototype). The prototype is replaced, not extended (see #4). |
| 9 | 2026-09-04 | Port order after Java: Elixir, Rust, Go, JS, PHP. | Elixir is the most different runtime and stress-tests the spec earliest; PHP is the hardest port and benefits most from a mature spec and conformance suite. |
| 10 | 2026-09-04 | Java targets the latest LTS (25), via Gradle toolchains; pipeline image is eclipse-temurin:25-jdk. | Owner call. Library consumers need Java 25+ from the next release. |
| 11 | 2026-09-04 | v3 membership: a per-mesh root ML-DSA keypair signs each node's identity into a membership certificate; a node proves membership by presenting a cert that verifies against the pinned root key. | Owner call among allowlist / root-signed / TOFU. Strongest of the three; CA-like trust without X.509; supports expiry and revocation. Resolves PLAN §8.1. |
| 12 | 2026-09-04 | The conformance runner and interop harnesses are written in Go. | Owner call (Go vs Rust). ML-KEM/X25519 in the stdlib, single static binaries, easy in reaper guests. Resolves PLAN §8.3. |
| 13 | 2026-09-04 | v3 relay trust is hop-by-hop: neighbors hold authenticated sessions and a relaying member decrypts and re-encrypts to the next hop. Mesh members trust each other; end-to-end payload protection against untrusted relays is deferred (format reserves room). | Follows from the members-trust-each-other model; keeps v3 tractable across six languages. Resolves PLAN §8.5 for v3. |

Open questions (undecided, tracked in [PLAN.md](PLAN.md) §8): reaper guest
strategy; publishing cadence. (Trust model, conformance-runner language, and
relay trust resolved above as #11-#13.)
