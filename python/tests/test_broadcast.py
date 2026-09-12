"""Broadcast tests (protocol.md section 6).

Both halves of the D5 fix are asserted, because D5 was two bugs in one line: the v2
implementation iterated indirect routes only, so direct session peers were missed,
and a node could appear among its own routes, so it broadcast to itself.
"""

from tests.conftest import until


def test_broadcast_reaches_every_peer_but_never_the_sender(run_async, spawn, issue):
    async def body():
        alpha = await spawn(issue("alpha"))
        beta = await spawn(issue("beta"))
        gamma = await spawn(issue("gamma"))

        beta_got, gamma_got, alpha_got = [], [], []
        beta.on_message(beta_got.append)
        gamma.on_message(gamma_got.append)
        alpha.on_message(alpha_got.append)

        await alpha.connect("127.0.0.1", beta.port())
        await alpha.connect("127.0.0.1", gamma.port())
        assert await until(lambda: "beta" in alpha.links and "gamma" in alpha.links)

        handed = alpha.broadcast({"m": "all"})
        assert handed == 2, f"broadcast handed off to {handed} destinations, want 2"
        assert await until(lambda: beta_got == [{"m": "all"}]), f"beta: {beta_got}"
        assert await until(lambda: gamma_got == [{"m": "all"}]), f"gamma: {gamma_got}"

        # Assert the absence with time allowed to pass, and after the positives, so a
        # failure reads as "the sender got its own broadcast" rather than as a timeout.
        assert not await until(lambda: len(alpha_got) > 0, timeout=1.0), \
            f"the sender received its own broadcast: {alpha_got}"

    run_async(body())


def test_broadcast_gives_each_destination_its_own_message_id(run_async, spawn, issue):
    # Forced, not stylistic: dedup keys on (mid, chunk index), so a shared mid would
    # have the first relay suppress every other copy, and an ack names only a mid.
    async def body():
        alpha = await spawn(issue("alpha"))
        beta = await spawn(issue("beta"))
        gamma = await spawn(issue("gamma"))

        acked = []
        alpha.on_ack(lambda a: acked.append(a.get("mid")))

        await alpha.connect("127.0.0.1", beta.port())
        await alpha.connect("127.0.0.1", gamma.port())
        assert await until(lambda: "beta" in alpha.links and "gamma" in alpha.links)

        assert alpha.broadcast({"m": "all"}) == 2
        assert await until(lambda: len(acked) == 2), f"expected one ack per destination: {acked}"
        assert len(set(acked)) == 2, f"both destinations acked the same mid: {acked}"

    run_async(body())


def test_broadcast_with_no_peers_reaches_nobody(run_async, spawn, issue):
    # The boundary: a lone node has no reachable labels, so the count is zero rather
    # than the node broadcasting to itself -- which is precisely the D5 failure.
    async def body():
        alpha = await spawn(issue("alpha"))
        got = []
        alpha.on_message(got.append)
        assert alpha.broadcast({"m": "all"}) == 0
        assert not await until(lambda: len(got) > 0, timeout=1.0), \
            f"a lone node broadcast to itself: {got}"

    run_async(body())
