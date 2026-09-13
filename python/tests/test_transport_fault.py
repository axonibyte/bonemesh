"""A transport-level fault closes the session, announced as `protocol-error`.

protocol.md §4 says frames are accepted strictly in order and "the session is
then torn down, because a gap means the stream is no longer the one the nonce
sequence describes". Four of the seven ports (go, rust, js, python) instead
dropped the frame and kept the link -- and because `receive_seq` advances only
on a *successful* open, the receiver then expects a `seq` the sender will never
send again. Every subsequent frame fails the same check, so the link is
permanently dead while both ends still believe it is up. With
`BONEMESH_IDLE_MS` defaulting to 0 there is no timer to reap it (D20).

The injection is a `seq` gap rather than a flipped ciphertext byte because it is
deterministic and exercises the ordering rule §4 actually states. A corrupted
ciphertext takes the same path (`TransportError` either way).

What these tests do NOT prove: that the *peer* re-dials and recovers. That is
tier 10's job over a real socket pair; here the claim is only that the link is
torn down rather than kept in a wedged state, and that the reason reaches the
far end.
"""

import pytest

from bonemesh import message
from bonemesh.transport import Transport
from tests.conftest import until


def _desync(node, peer: str) -> None:
    """Skip one send seq, so the peer's next frame is a gap it must reject."""
    node.links[peer].transport.send_seq += 1


def test_an_out_of_order_frame_tears_the_session_down(run_async, spawn, issue):
    async def body():
        beta = await spawn(issue("beta"))
        alpha = await spawn(issue("alpha"))
        await alpha.connect("127.0.0.1", beta.port())
        assert await until(lambda: "beta" in alpha.links and "alpha" in beta.links)

        _desync(alpha, "beta")
        alpha._send_to_link("beta", message.data("m-gap", "alpha", "beta", 16, {"x": 1}))

        assert await until(lambda: "alpha" not in beta.links), \
            "beta kept a session whose nonce stream it can never follow again"
    run_async(body())


def test_the_teardown_is_announced_as_protocol_error(run_async, spawn, issue):
    async def body():
        beta = await spawn(issue("beta"))
        alpha = await spawn(issue("alpha"))
        await alpha.connect("127.0.0.1", beta.port())
        assert await until(lambda: "beta" in alpha.links and "alpha" in beta.links)

        # Record what alpha opens, so the reason is read off the wire rather than
        # inferred from the close. Two oracles: the link drops (above) AND the
        # peer is told why (here).
        seen: list[dict] = []
        link = alpha.links["beta"]
        inner_open = link.transport.open

        def recording(carrier):
            msg = inner_open(carrier)
            seen.append(msg)
            return msg

        link.transport.open = recording

        _desync(alpha, "beta")
        alpha._send_to_link("beta", message.data("m-gap", "alpha", "beta", 16, {"x": 1}))

        assert await until(
            lambda: any(m.get("type") == "bye" for m in seen)
        ), f"beta closed without saying why; alpha saw {seen}"
        byes = [m for m in seen if m.get("type") == "bye"]
        assert byes[0].get("reason") == "protocol-error", \
            f"wrong close reason: {byes[0]}"
    run_async(body())


def test_an_unrecognized_inner_type_does_not_close_the_session(run_async, spawn, issue):
    """§8 requires ignoring unknown inner types -- so they are NOT protocol errors.

    This is the guard on the fix above: it would be easy to make every
    unparseable thing close the link, which would break forward compatibility.
    """
    async def body():
        beta = await spawn(issue("beta"))
        alpha = await spawn(issue("alpha"))
        await alpha.connect("127.0.0.1", beta.port())
        assert await until(lambda: "beta" in alpha.links and "alpha" in beta.links)

        alpha._send_to_link("beta", {"type": "quux-from-the-future", "mid": "m1"})
        # Assert the absence with time allowed to pass, and prove the link is
        # still *usable* afterwards rather than merely still listed.
        assert not await until(lambda: "alpha" not in beta.links, timeout=1.5), \
            "beta closed the session over an inner type it is required to ignore"
        got: list = []
        beta.on_message(got.append)
        alpha._send_to_link("beta", message.data("m-ok", "alpha", "beta", 16, {"x": 2}))
        assert await until(lambda: got != []), \
            "the link survived the unknown type but could no longer carry data"
    run_async(body())


def test_the_bye_goes_out_on_the_faulting_link_not_the_current_one(run_async, spawn, issue):
    """A reconnect must not redirect one link's fault onto another link.

    Between the fault and the announcement a different link can become current
    for that peer; sealing this link's fault with that link's keys would write a
    frame the peer cannot open, on a session that is fine. This is a white-box
    property about which socket is written: a stale stand-in supplies the two
    attributes `_protocol_error` touches, so the live link is left alone (both to
    keep its socket intact and so its untouched counter can serve as the second
    oracle).
    """
    async def body():
        beta = await spawn(issue("beta"))
        alpha = await spawn(issue("alpha"))
        await alpha.connect("127.0.0.1", beta.port())
        assert await until(lambda: "beta" in alpha.links)

        current = alpha.links["beta"]
        before = current.transport.send_seq
        written: list[bytes] = []

        class _StaleWriter:
            def write(self, data):
                written.append(data)

        class _StaleLink:
            writer = _StaleWriter()
            transport = Transport(b"\x11" * 32, b"\x22" * 32)

        alpha._protocol_error(_StaleLink())

        # Two oracles: the stale link was written to, AND the live link's nonce
        # counter never moved -- a frame sealed on it would have advanced it.
        assert len(written) == 1, f"expected one frame on the stale link, got {written}"
        assert current.transport.send_seq == before, \
            "the bye was sealed on the live link instead of the faulting one"
    run_async(body())
