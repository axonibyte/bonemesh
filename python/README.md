# BoneMesh — Python

The Python implementation of BoneMesh v3: a full routing mesh node, wire-compatible
with the Java, Go, Rust, PHP, Elixir and JavaScript implementations. Built on
`asyncio`, which is the closest structural match to the JS port — a single event
loop means there is no shared-state race to guard.

Requires Python 3.12+ and one runtime dependency, `cryptography`, for X25519,
ML-KEM-768, ML-DSA-65/87, HKDF-SHA-256 and ChaCha20-Poly1305 over OpenSSL 3.5.
CPython's stdlib has no post-quantum primitives, so unlike the JS and Elixir ports
this one cannot be dependency-free. It is the only dependency, and its whole
transitive set is licence-gated (see below).

## Test

```sh
cd python
uv sync --locked
uv run pytest -q
uv run tools/check_licenses.py
```

This is what the `bonemesh-python` reaper tenant (`python/.reaper.toml`) runs.

> On a host with no `cryptography` wheel — FreeBSD, notably — the first `uv sync`
> compiles it from source and takes several minutes. It needs Rust and the OpenSSL
> headers, both of which that host has. Set `BONEMESH_PY` to an interpreter that
> already has `cryptography` installed to skip the venv entirely.

## Licensing

BoneMesh is Apache-2.0, which is one-way incompatible with GPL-2.0, so a copyleft
dependency anywhere in the transitive set would be disqualifying.
`tools/check_licenses.py` gates every installed distribution against an explicit
permissive allowlist and runs in CI and in the reaper tenant, so a future
`uv lock` that pulls in something incompatible **fails the build** rather than
shipping quietly. It is self-tested (`--self-test`) against synthetic GPL, LGPL,
MPL, unknown and absent licences — and against an empty environment, which must
fail rather than pass, because an allowlist that never rejects anything is
indistinguishable from no allowlist and a gate that inspects nothing is worse than
none.

## Interop

The neutral driver is [`../interop/drivers/python.sh`](../interop/drivers/python.sh)
(`keygen` / `listen` / `connect` / `mesh`, plus `caps` and the `--acks` /
`--sessions` observability flags). See [`../interop/README.md`](../interop/README.md)
and [`../docs/testing.md`](../docs/testing.md).

The seven corpus checks are `../interop/check-{canon,framing,messages,keyschedule,agreement,pqc,transport}-python.sh`.
They share one launcher, [`../interop/python-run.sh`](../interop/python-run.sh), so
the venv bootstrap is written once — and it deliberately does **not** live in
`interop/drivers/`, because that directory is the implementation registry and
anything in it is discovered as a language.

## Scripts

Every entry point under `bin/` is a PEP 723 script: it carries its own inline
dependency metadata and a `#!/usr/bin/env -S uv run --script` shebang, so it runs
standalone without activating anything.

```sh
./bin/canon_check.py ../spec/corpus/canon.json
```

`tools/check_licenses.py` is deliberately **not** one. `uv run` treats any file
carrying inline script metadata as an *isolated* script and gives it a fresh
environment holding only its declared dependencies — so as a PEP 723 script with no
dependencies, the licence gate audited an empty environment and passed trivially.
It now has no inline metadata, so `uv run tools/check_licenses.py` uses the project
environment, and it refuses to report success if it cannot see the dependency it
exists to audit.

The interop driver is invoked through the venv rather than `uv run`, because uv
re-resolves the environment per invocation and the harness calls the driver many
times — a slow health probe reads as an unavailable driver.

## Embedding

```python
import asyncio
from bonemesh import Node
from bonemesh.node import Config

async def main():
    node = await Node.start(Config(label, mesh, root_public, cert, id_private), 7000)
    node.on_message(lambda payload: print("got", payload))
    node.on_ack(lambda inner: print("ack/nak", inner))
    await node.connect("peer.example.com", 7000)
    mid, ok = node.send_mid("other-label", {"hello": "mesh"})
    ...
    node.kill()

asyncio.run(main())
```

`send` / `send_mid`, `on_message` / `on_ack`, `route_table`, `session_info` and
`kill` mirror the other six ports. The worked example, alongside every other
language, is in [`../docs/user-guide.md`](../docs/user-guide.md) §5.
