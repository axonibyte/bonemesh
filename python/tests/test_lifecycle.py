"""Session lifecycle: the simultaneous-dial tiebreak, reconnects, and teardown.

F1 (the dial tiebreak) is deliberately covered here rather than by interop tier
10: the tier cannot force a genuine dial collision reliably, so it is proven
per-language instead, in both registration orders and both label orderings
(interop/tier10.sh lines 18-23 say exactly this).
"""

import asyncio

import pytest

from bonemesh.node import Config, Node
from tests.conftest import until


def test_a_graceful_bye_tears_the_session_down(run_async, spawn, issue):
    async def body():
        from bonemesh import message
        beta = await spawn(issue("beta"))
        alpha = await spawn(issue("alpha"))
        await alpha.connect("127.0.0.1", beta.port())
        assert await until(lambda: "alpha" in beta.links)
        alpha._send_to_link("beta", message.bye("shutdown"))
        assert await until(lambda: "alpha" not in beta.links), \
            "beta kept the session after a bye"
    run_async(body())


def test_a_dropped_link_withdraws_its_routes(run_async, spawn, issue):
    async def body():
        beta = await spawn(issue("beta"))
        alpha = await spawn(issue("alpha"))
        await alpha.connect("127.0.0.1", beta.port())
        # Wait for BOTH ends: "beta" appears in alpha.links as soon as ALPHA
        # registers, which can precede beta finishing its own registration. Killing
        # in that window closes nothing on beta's side, because server.close() does
        # not close already-accepted sockets -- so the test would be racy rather
        # than wrong.
        assert await until(lambda: "beta" in alpha.links and "alpha" in beta.links)
        assert alpha.table.next_hop("beta") == "beta"
        beta.kill()
        assert await until(lambda: alpha.table.next_hop("beta") is None), \
            "alpha kept a route to a dead neighbour"
        assert "beta" not in alpha.links
    run_async(body())


def test_a_reconnect_replaces_the_link_without_withdrawing_its_routes(run_async, spawn, issue):
    """A displaced link's deregister is identity-guarded.

    The stale link's close must not withdraw the live link's routes -- the same
    white-box property the Go port's internal_test.go covers.
    """
    async def body():
        beta = await spawn(issue("beta"))
        alpha = await spawn(issue("alpha"))
        await alpha.connect("127.0.0.1", beta.port())
        assert await until(lambda: "beta" in alpha.links)
        first = alpha.links["beta"]
        await alpha.connect("127.0.0.1", beta.port())
        assert await until(lambda: alpha.links.get("beta") is not first)
        await asyncio.sleep(0.4)  # let the displaced link's close fire
        assert "beta" in alpha.links, "the stale link's death withdrew the live link"
        assert alpha.table.next_hop("beta") == "beta"
    run_async(body())


@pytest.mark.parametrize("lower_dials", [True, False])
def test_simultaneous_dial_converges_on_one_session(run_async, issue, lower_dials):
    """F1: both ends keep the session initiated by the lower-labelled node.

    Run both ways round, so a tiebreak that happens to favour whoever dialled
    second cannot pass by luck.
    """
    async def body():
        # "alpha" < "zulu", so alpha is the lower-labelled node.
        low = await Node.start(issue("alpha"), 0)
        high = await Node.start(issue("zulu"), 0)
        try:
            if lower_dials:
                await low.connect("127.0.0.1", high.port())
                await high.connect("127.0.0.1", low.port())
            else:
                await high.connect("127.0.0.1", low.port())
                await low.connect("127.0.0.1", high.port())
            await asyncio.sleep(0.6)
            # Exactly one session each way, and both ends agree which one.
            assert len(low.links) == 1 and len(high.links) == 1
            assert low.links["zulu"].initiator is True, \
                "the surviving session is not the one alpha initiated"
            assert high.links["alpha"].initiator is False
            assert low.links["zulu"].th == high.links["alpha"].th
        finally:
            low.kill()
            high.kill()
    run_async(body())


def test_probe_timeout_declares_a_silent_neighbour_dead(run_async, issue, monkeypatch):
    """F3: a peer that stops answering probes is withdrawn."""
    async def body():
        monkeypatch.setenv("BONEMESH_PROBE_TIMEOUT_MS", "1200")
        beta = await Node.start(issue("beta"), 0)
        alpha = await Node.start(issue("alpha"), 0)
        try:
            await alpha.connect("127.0.0.1", beta.port())
            assert await until(lambda: "beta" in alpha.links and "alpha" in beta.links)

            # Silence beta without closing anything: stub out its only path to the
            # wire, so it keeps reading but emits no echo, probe or disco.
            # Cancelling its reader instead would close the link and alpha would
            # notice via EOF -- passing the test through the wrong mechanism.
            beta._send_to_link = lambda label, inner: True

            assert await until(lambda: "beta" not in alpha.links, timeout=8.0), \
                "alpha kept a neighbour that stopped answering probes"
            assert alpha.table.next_hop("beta") is None
            # The socket was never closed by beta, so this can only have been the
            # probe timeout.
            assert not beta.links or "alpha" in beta.links
        finally:
            alpha.kill()
            beta.kill()
    run_async(body())


def test_idle_teardown_closes_a_data_idle_link(run_async, issue, monkeypatch):
    """F4: probe/echo/disco traffic does not count as activity, only data does."""
    async def body():
        monkeypatch.setenv("BONEMESH_IDLE_MS", "1500")
        beta = await Node.start(issue("beta"), 0)
        alpha = await Node.start(issue("alpha"), 0)
        try:
            await alpha.connect("127.0.0.1", beta.port())
            assert await until(lambda: "beta" in alpha.links)
            # The heartbeat keeps exchanging probes and disco the whole time; only
            # the absence of *data* may trigger the teardown.
            assert await until(lambda: "beta" not in alpha.links, timeout=8.0), \
                "an idle link was never torn down"
        finally:
            alpha.kill()
            beta.kill()
    run_async(body())


def test_idle_teardown_is_off_by_default(run_async, spawn, issue):
    async def body():
        beta = await spawn(issue("beta"))
        alpha = await spawn(issue("alpha"))
        await alpha.connect("127.0.0.1", beta.port())
        assert await until(lambda: "beta" in alpha.links)
        assert alpha.tun.idle_ms == 0
        await asyncio.sleep(2.5)
        assert "beta" in alpha.links, "a link was torn down with idle teardown disabled"
    run_async(body())
