"""Shared fixtures.

The mesh root is generated per-session rather than fixed, because ML-DSA keygen is
fast and a committed private key in a test tree is a bad habit even for a test
root. Certificate windows are derived from the wall clock: a live node judges
validity against it, so a hardcoded instant makes the suite expire (see D10 in
docs/defects.md, which is exactly that bug in the Rust suite).
"""

from __future__ import annotations

import asyncio
import time

import pytest

from bonemesh import cert as certmod
from bonemesh import crypto
from bonemesh.node import Config, Node

MESH = "acme-prod"


@pytest.fixture(scope="session")
def root():
    """(public, private_seed) for a mesh root."""
    return crypto.mldsa87_generate()


@pytest.fixture
def issue(root):
    """issue(label) -> Config, with a certificate valid around now."""
    root_pub, root_priv = root

    def _issue(label: str, *, nbf_delta: int = -100, exp_delta: int = 3600) -> Config:
        now = int(time.time())
        pub, priv = crypto.mldsa65_generate()
        cert = certmod.sign(
            certmod.build(MESH, label, pub, now + nbf_delta, now + exp_delta), root_priv
        )
        return Config(label, MESH, root_pub, cert, priv)

    return _issue


@pytest.fixture
def spawn():
    """Start nodes and guarantee they are killed, even on failure."""
    started: list[Node] = []

    async def _spawn(config: Config, port: int = 0) -> Node:
        node = await Node.start(config, port)
        started.append(node)
        return node

    yield _spawn
    for node in started:
        node.kill()


async def until(predicate, timeout: float = 10.0, interval: float = 0.05) -> bool:
    """Wait for a predicate, returning whether it came true.

    Callers assert on the *thing they wanted*, not on this return value, so a
    failure reads as "the payload never arrived" rather than as a bare timeout.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(interval)
    return False


@pytest.fixture
def run_async():
    """Run one coroutine on a fresh event loop.

    The suite avoids pytest-asyncio so the only dependency stays `cryptography`;
    each test owns its loop, which also stops a leaked task from one test being
    observed by the next.
    """
    def _run(coro):
        return asyncio.run(coro)

    return _run
