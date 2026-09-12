"""Session rekey (F5) and retry/backoff (F2).

These set BONEMESH_* overrides, which are read once at node start, so each test
starts its own nodes after monkeypatching rather than sharing a fixture -- the same
isolation the Rust port achieves by putting these suites in separate binaries.
"""

import asyncio

from bonemesh.node import Node
from tests.conftest import until


def test_rekey_advances_the_epoch_on_both_ends_and_keeps_delivering(run_async, issue, monkeypatch):
    async def body():
        # A low frame threshold so a handful of sends triggers the rekey.
        monkeypatch.setenv("BONEMESH_REKEY_FRAMES", "6")
        beta = await Node.start(issue("beta"), 0)
        alpha = await Node.start(issue("alpha"), 0)
        try:
            got = []
            beta.on_message(got.append)
            await alpha.connect("127.0.0.1", beta.port())
            assert await until(lambda: "beta" in alpha.links and "alpha" in beta.links)

            for i in range(10):
                alpha.send("beta", {"n": i})
                await asyncio.sleep(0.05)

            assert await until(
                lambda: alpha.session_info()["beta"]["epoch"] >= 1
                and beta.session_info()["alpha"]["epoch"] >= 1,
                timeout=15.0,
            ), (f"epochs never advanced: alpha={alpha.session_info()} "
                f"beta={beta.session_info()}")

            # Both ends agree on the NEW transcript hash, not just the epoch.
            assert alpha.session_info()["beta"]["th"] == beta.session_info()["alpha"]["th"]

            # Delivery survives the key swap: this is the half that matters.
            before = len(got)
            assert alpha.send("beta", {"after": "rekey"})
            assert await until(lambda: len(got) > before), "delivery stopped after the rekey"
            assert got[-1] == {"after": "rekey"}
        finally:
            alpha.kill()
            beta.kill()
    run_async(body())


def test_only_the_session_initiator_starts_a_rekey(run_async, issue, monkeypatch):
    async def body():
        monkeypatch.setenv("BONEMESH_REKEY_FRAMES", "2")
        beta = await Node.start(issue("beta"), 0)
        alpha = await Node.start(issue("alpha"), 0)
        try:
            await alpha.connect("127.0.0.1", beta.port())
            assert await until(lambda: "beta" in alpha.links and "alpha" in beta.links)
            assert alpha.links["beta"].initiator is True
            assert beta.links["alpha"].initiator is False
            # The responder must not start one of its own; the epoch still advances
            # exactly once per initiator-driven exchange.
            assert await until(lambda: alpha.session_info()["beta"]["epoch"] >= 1,
                               timeout=15.0)
            await asyncio.sleep(1.2)
            assert alpha.session_info()["beta"]["epoch"] == beta.session_info()["alpha"]["epoch"]
        finally:
            alpha.kill()
            beta.kill()
    run_async(body())


def test_a_stalled_rekey_is_abandoned_and_the_old_keys_keep_working(run_async, issue, monkeypatch):
    """The safe degrade against a peer that ignores rekey frames."""
    async def body():
        monkeypatch.setenv("BONEMESH_REKEY_FRAMES", "2")
        monkeypatch.setenv("BONEMESH_REKEY_TIMEOUT_MS", "1200")
        beta = await Node.start(issue("beta"), 0)
        alpha = await Node.start(issue("alpha"), 0)
        try:
            got = []
            beta.on_message(got.append)
            await alpha.connect("127.0.0.1", beta.port())
            assert await until(lambda: "beta" in alpha.links and "alpha" in beta.links)

            # Make beta behave like a peer with no rekey support: ignore the frames.
            beta._handle_rekey = lambda link, msg: None

            alpha.send("beta", {"n": 1})
            alpha.send("beta", {"n": 2})
            assert await until(lambda: alpha.links["beta"].rekey_hs is not None, timeout=10.0), \
                "the initiator never attempted a rekey"
            assert await until(lambda: alpha.links["beta"].rekey_hs is None, timeout=10.0), \
                "the stalled rekey was never abandoned"

            # Old keys still work, and the epoch never advanced.
            assert alpha.session_info()["beta"]["epoch"] == 0
            before = len(got)
            assert alpha.send("beta", {"still": "working"})
            assert await until(lambda: len(got) > before), \
                "the old keys stopped working after an abandoned rekey"
        finally:
            alpha.kill()
            beta.kill()
    run_async(body())


def test_a_queued_send_is_retried_once_a_route_appears(run_async, issue, monkeypatch):
    async def body():
        monkeypatch.setenv("BONEMESH_RETRY_BASE_MS", "200")
        beta = await Node.start(issue("beta"), 0)
        alpha = await Node.start(issue("alpha"), 0)
        try:
            got = []
            beta.on_message(got.append)
            # Send before there is any link at all: it must queue, not vanish.
            mid, ok = alpha.send_mid("beta", {"queued": True})
            assert not ok and "beta" in alpha.pending
            await alpha.connect("127.0.0.1", beta.port())
            assert await until(lambda: got, timeout=15.0), \
                "a queued message was never retried once the route appeared"
            assert got == [{"queued": True}]
            assert "beta" not in alpha.pending
        finally:
            alpha.kill()
            beta.kill()
    run_async(body())


def test_an_undeliverable_send_expires_into_a_synthesized_nak(run_async, issue, monkeypatch):
    async def body():
        monkeypatch.setenv("BONEMESH_RETRY_BASE_MS", "200")
        monkeypatch.setenv("BONEMESH_RETRY_MAX_MS", "1200")
        alpha = await Node.start(issue("alpha"), 0)
        try:
            acks = []
            alpha.on_ack(acks.append)
            mid, ok = alpha.send_mid("nowhere", {"doomed": True})
            assert not ok
            assert await until(lambda: acks, timeout=15.0), \
                "no expiry NAK was reported to the origin"
            nak = acks[0]
            assert nak["type"] == "nak" and nak["mid"] == mid
            assert nak["reason"] == "expired" and nak["hop"] == "alpha"
            assert "nowhere" not in alpha.pending
        finally:
            alpha.kill()
    run_async(body())


def test_retry_can_be_disabled_entirely(run_async, issue, monkeypatch):
    async def body():
        monkeypatch.setenv("BONEMESH_RETRY_MAX_MS", "0")
        alpha = await Node.start(issue("alpha"), 0)
        try:
            assert alpha.tun.retry_max_ms == 0
            mid, ok = alpha.send_mid("nowhere", {"x": 1})
            assert not ok
            assert alpha.pending == {}, "a send was queued with retry disabled"
        finally:
            alpha.kill()
    run_async(body())


def test_the_retry_queue_is_bounded_per_destination(run_async, issue):
    async def body():
        alpha = await Node.start(issue("alpha"), 0)
        try:
            for _ in range(200):
                alpha.send("nowhere", {"x": 1})
            assert len(alpha.pending["nowhere"]) == 64
        finally:
            alpha.kill()
    run_async(body())
