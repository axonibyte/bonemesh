"""Live nodes over loopback: handshake, delivery, relay, ack and NAK."""

import asyncio

import pytest

from tests.conftest import until


async def _two(spawn, issue):
    beta = await spawn(issue("beta"))
    alpha = await spawn(issue("alpha"))
    got = []
    beta.on_message(got.append)
    acks = []
    alpha.on_ack(acks.append)
    peer = await alpha.connect("127.0.0.1", beta.port())
    return alpha, beta, got, acks, peer


def test_handshake_and_delivery_between_two_nodes(run_async, spawn, issue):
    async def body():
        alpha, beta, got, acks, peer = await _two(spawn, issue)
        assert peer == "beta"
        mid, ok = alpha.send_mid("beta", {"probe": "hello"})
        assert ok
        assert await until(lambda: got), "payload never arrived at beta"
        assert got == [{"probe": "hello"}]
        # F6: the destination acknowledges back to the origin.
        assert await until(lambda: any(a["type"] == "ack" and a["mid"] == mid for a in acks)), \
            "origin never received the ack"
    run_async(body())


def test_both_ends_agree_on_the_transcript_hash_label(run_async, spawn, issue):
    async def body():
        alpha, beta, _, _, _ = await _two(spawn, issue)
        assert await until(lambda: alpha.session_info() and beta.session_info())
        th_a = alpha.session_info()["beta"]["th"]
        th_b = beta.session_info()["alpha"]["th"]
        assert th_a and th_a == th_b
        assert alpha.session_info()["beta"]["epoch"] == 0
    run_async(body())


def test_a_send_with_no_route_reports_failure(run_async, spawn, issue):
    async def body():
        alpha = await spawn(issue("alpha"))
        mid, ok = alpha.send_mid("nobody", {"x": 1})
        assert not ok and mid
        # F2: it is queued for retry rather than thrown away.
        assert "nobody" in alpha.pending
    run_async(body())


def test_a_foreign_mesh_peer_cannot_establish_a_session(run_async, spawn, issue, root):
    async def body():
        from bonemesh import cert as certmod, crypto
        from bonemesh.node import Config
        import time
        beta = await spawn(issue("beta"))
        got = []
        beta.on_message(got.append)

        # An intruder holding a certificate from a DIFFERENT root, for a label
        # inside the real mesh.
        foreign_pub, foreign_priv = crypto.mldsa87_generate()
        now = int(time.time())
        pub, priv = crypto.mldsa65_generate()
        cert = certmod.sign(
            certmod.build("acme-prod", "alpha", pub, now - 100, now + 3600), foreign_priv)
        intruder = await spawn(Config("alpha", "acme-prod", foreign_pub, cert, priv))

        with pytest.raises(Exception):
            await intruder.connect("127.0.0.1", beta.port())
        # Two oracles: the intruder has no session, and nothing was delivered.
        assert intruder.links == {}
        await asyncio.sleep(0.3)
        assert got == [], "an unauthenticated payload was delivered"
    run_async(body())


def test_three_node_line_relays_across_the_middle_hop(run_async, spawn, issue):
    async def body():
        alpha = await spawn(issue("alpha"))
        bravo = await spawn(issue("bravo"))
        charlie = await spawn(issue("charlie"))
        got = []
        charlie.on_message(got.append)
        acks = []
        alpha.on_ack(acks.append)
        await alpha.connect("127.0.0.1", bravo.port())
        await charlie.connect("127.0.0.1", bravo.port())

        assert await until(lambda: alpha.table.next_hop("charlie") == "bravo"), \
            f"routes never converged: {alpha.route_table()}"
        mid, ok = alpha.send_mid("charlie", {"relayed": True})
        assert ok
        assert await until(lambda: got), "relayed payload never arrived"
        assert got == [{"relayed": True}]
        # The ack travels back through the relay to the origin.
        assert await until(lambda: any(a["type"] == "ack" and a["mid"] == mid for a in acks)), \
            "ack never made it back through the relay"
    run_async(body())


def test_ttl_exhaustion_naks_naming_the_relay_not_the_destination(run_async, spawn, issue):
    """D4: the relay that dropped the message names itself as the failing hop."""
    async def body():
        alpha = await spawn(issue("alpha"))
        bravo = await spawn(issue("bravo"))
        charlie = await spawn(issue("charlie"))
        acks = []
        alpha.on_ack(acks.append)
        await alpha.connect("127.0.0.1", bravo.port())
        await charlie.connect("127.0.0.1", bravo.port())
        assert await until(lambda: alpha.table.next_hop("charlie") == "bravo")

        alpha._send_with_ttl("charlie", {"doomed": True}, 1)
        assert await until(lambda: any(a["type"] == "nak" for a in acks)), "no NAK arrived"
        nak = next(a for a in acks if a["type"] == "nak")
        assert nak["hop"] == "bravo", f"named {nak['hop']!r}, not the relay"
        assert nak["reason"] == "ttl"
    run_async(body())


def test_a_duplicate_message_id_is_delivered_only_once(run_async, spawn, issue):
    async def body():
        alpha, beta, got, _, _ = await _two(spawn, issue)
        assert await until(lambda: "beta" in alpha.links)
        from bonemesh import message
        mid = message.new_mid()
        msg = message.data(mid, "alpha", "beta", 16, {"dup": True})
        alpha._send_to_link("beta", msg)
        alpha._send_to_link("beta", dict(msg))
        assert await until(lambda: got)
        await asyncio.sleep(0.3)
        assert got == [{"dup": True}], f"deduplication failed: {got}"
    run_async(body())


def test_kill_closes_the_listener_and_drops_links(run_async, spawn, issue):
    async def body():
        alpha, beta, _, _, _ = await _two(spawn, issue)
        assert alpha.links
        alpha.kill()
        await asyncio.sleep(0.2)
        assert alpha.links == {}
    run_async(body())


def test_repeatedly_rejected_dials_do_not_leak_sockets(run_async, spawn, issue):
    """A dial that fails past the connect must close its socket.

    Without this, every rejected handshake leaked a file descriptor, and tier 9's
    nemesis churn dials with a foreign-root certificate over and over -- so the
    leak was unbounded. Counting descriptors directly is the oracle; the defect
    originally surfaced only as an "exception ignored in StreamWriter.__del__"
    warning, which is too incidental to rely on.
    """
    async def body():
        import gc
        import os
        import time

        from bonemesh import cert as certmod
        from bonemesh import crypto
        from bonemesh.node import Config

        beta = await spawn(issue("beta"))
        foreign_pub, foreign_priv = crypto.mldsa87_generate()
        now = int(time.time())
        pub, priv = crypto.mldsa65_generate()
        cert = certmod.sign(
            certmod.build("acme-prod", "alpha", pub, now - 100, now + 3600), foreign_priv)
        intruder = await spawn(Config("alpha", "acme-prod", foreign_pub, cert, priv))

        def fd_count():
            gc.collect()
            try:
                return len(os.listdir(f"/dev/fd/{os.getpid()}"))
            except OSError:
                return len(os.listdir("/dev/fd"))

        for _ in range(3):  # warm up, so one-off allocations are not counted
            with pytest.raises(Exception):
                await intruder.connect("127.0.0.1", beta.port())
        await asyncio.sleep(0.1)
        before = fd_count()
        for _ in range(12):
            with pytest.raises(Exception):
                await intruder.connect("127.0.0.1", beta.port())
        await asyncio.sleep(0.2)
        after = fd_count()
        assert after - before <= 2, (
            f"{after - before} descriptors leaked across 12 rejected dials"
        )
    run_async(body())
