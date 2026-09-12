"""A valid transport frame carrying a garbage inner message.

Interop tier 5 and tier 7 inject faults at the framing, handshake and AEAD layers:
non-JSON, oversize, truncated, wrong-mesh bmx1, tampered bmx3, corrupted carriers.
None of them produce a *correctly sealed* frame whose inner message is structurally
wrong, because the fault peer and the fuzzer both corrupt below that layer.

That leaves the inner-message handlers untested against hostile input from an
AUTHENTICATED peer -- which is a real position: a peer inside the mesh, running a
different or older implementation, or simply buggy. A handler that raises there
takes the reader task down and kills a healthy session.

Two oracles, both needed: nothing spurious is delivered, and the link is still
alive and still delivering afterwards. The second is what catches a handler that
kills the session while correctly refusing the message.
"""

import asyncio

from bonemesh.node import Node
from tests.conftest import until

GOOD_MID = "0123456789abcdef0123456789abcdef"

# Each is a structurally valid JSON object that a conforming peer would never
# send. None may be delivered, and none may kill the session.
#
# `bye` is deliberately NOT in here even though it is an obvious thing to fuzz: it
# is a legitimate teardown, so including it required the survival oracle to tolerate
# a dropped link -- and that tolerance then hid a link killed by a crashing handler,
# which is the entire defect class this suite exists to catch. bye is covered by
# test_lifecycle instead.
HOSTILE = [
    {"type": "data"},                                             # nothing else at all
    {"type": "data", "mid": None, "to": None, "from": None, "ttl": None, "payload": None},
    {"type": "data", "mid": 12345, "to": [], "from": {}, "ttl": 1.5, "payload": []},
    {"type": "echo", "token": "not-a-number"},
    {"type": "echo"},
    {"type": "probe", "token": None},
    {"type": "disco", "routes": "not-an-object"},
    {"type": "disco", "routes": {"gamma": "not-a-number"}},
    {"type": "disco", "routes": {"gamma": None}},
    {"type": "disco"},
    {"type": "ack"},
    {"type": "ack", "mid": None, "to": None, "ttl": None},
    {"type": "nak", "mid": GOOD_MID},
    {"type": "nak", "mid": GOOD_MID, "to": "alpha", "ttl": "x", "hop": None, "reason": None},
    {"type": "rekey"},
    {"type": "rekey", "phase": 1, "body": "not base64"},
    {"type": "rekey", "phase": 1, "body": ""},
    {"type": "rekey", "phase": 99},
    {"type": "rekey", "phase": "one", "body": "AAAA"},
    {"type": "completely-unknown-to-this-version", "whatever": 1},
    {"type": None},
    {"no-type-field-at-all": True},
    {},
]


def test_a_garbage_inner_message_is_refused_without_killing_the_session(run_async, spawn, issue):
    async def body():
        beta = await spawn(issue("beta"))
        alpha = await spawn(issue("alpha"))
        got = []
        beta.on_message(got.append)
        await alpha.connect("127.0.0.1", beta.port())
        assert await until(lambda: "beta" in alpha.links and "alpha" in beta.links)

        link = alpha.links["beta"]
        for hostile in HOSTILE:
            # Sealed on a real session, so it arrives authenticated and in order:
            # the inner handlers are genuinely what is under test.
            link.writer.write(__import__("bonemesh.frame", fromlist=["encode"]).encode(
                link.transport.seal(hostile)))
        await asyncio.sleep(0.1)

        # Oracle 1 -- the precondition, asserted BEFORE the success indicator, so a
        # failure reads as "it delivered garbage" rather than as a missing signal.
        assert got == [], f"a garbage inner message was delivered: {got}"

        # Oracle 2 -- the SAME session survived all of it and still works. No
        # redialing: nothing in the battery is a legitimate teardown, so a dropped
        # link means a handler crashed and took the reader with it.
        assert "alpha" in beta.links, "the battery killed beta's session"
        assert "beta" in alpha.links, "the battery killed alpha's session"
        assert not link.pump.done(), "alpha's reader task died on a garbage inner message"
        assert alpha.send("beta", {"after": "the battery"}), "send failed after the battery"
        assert await until(lambda: got), "delivery never resumed after the battery"
        assert got == [{"after": "the battery"}]
    run_async(body())


def test_a_destination_addressed_message_is_delivered_regardless_of_ttl(run_async, spawn, issue):
    """`ttl` bounds RELAYING, not admission.

    A message that has arrived at its destination is delivered whatever its ttl
    says -- the hop limit has already done its job. This was the second thing the
    hostile battery got wrong on first run: a `ttl` of "sixteen" or -5 addressed to
    the receiver looks malformed but is deliverable, and the JS reference delivers
    it too. Treating it as must-not-deliver would have made this port stricter than
    the wire, which is a divergence, not a hardening.
    """
    async def body():
        from bonemesh.frame import encode
        from bonemesh.message import new_mid
        beta = await spawn(issue("beta"))
        alpha = await spawn(issue("alpha"))
        got = []
        beta.on_message(got.append)
        await alpha.connect("127.0.0.1", beta.port())
        assert await until(lambda: "beta" in alpha.links and "alpha" in beta.links)
        link = alpha.links["beta"]
        for ttl in ("sixteen", -5, 0, None, 255):
            link.writer.write(encode(link.transport.seal({
                "type": "data", "mid": new_mid(), "to": "beta", "from": "alpha",
                "ttl": ttl, "payload": {"ttl_was": repr(ttl)}})))
        assert await until(lambda: len(got) == 5), f"delivered {len(got)} of 5: {got}"
    run_async(body())


def test_a_malformed_chunk_field_does_not_block_delivery(run_async, spawn, issue):
    """A garbage `chunk` is tolerated, not fatal -- and the JS reference agrees.

    `chunk` only feeds the dedup key (`d:<mid>:<i>`), so a non-object or
    non-numeric index resolves to -1 and the payload is still delivered. This is
    the case that made the hostile battery above fail on first run: it had been
    written as must-not-deliver, which would have been a divergence from every
    other port rather than a defect in this one.
    """
    async def body():
        from bonemesh.frame import encode
        beta = await spawn(issue("beta"))
        alpha = await spawn(issue("alpha"))
        got = []
        beta.on_message(got.append)
        await alpha.connect("127.0.0.1", beta.port())
        assert await until(lambda: "beta" in alpha.links and "alpha" in beta.links)
        link = alpha.links["beta"]
        for chunk in ("not-an-object", {"i": "zero"}, {"n": 3}, [], None):
            link.writer.write(encode(link.transport.seal({
                "type": "data", "mid": __import__("bonemesh.message", fromlist=["new_mid"]).new_mid(),
                "to": "beta", "from": "alpha", "ttl": 16,
                "payload": {"chunk_was": repr(chunk)}, "chunk": chunk})))
        assert await until(lambda: len(got) == 5), f"delivered {len(got)} of 5: {got}"
    run_async(body())


def test_the_listener_survives_a_garbage_inner_from_an_authenticated_peer(run_async, spawn, issue):
    """The same battery aimed the other way, with the listener as the victim."""
    async def body():
        beta = await spawn(issue("beta"))
        alpha = await spawn(issue("alpha"))
        received = []
        alpha.on_message(received.append)
        await alpha.connect("127.0.0.1", beta.port())
        assert await until(lambda: "alpha" in beta.links)

        link = beta.links["alpha"]
        from bonemesh.frame import encode
        for hostile in HOSTILE:
            link.writer.write(encode(link.transport.seal(hostile)))
        await asyncio.sleep(0.1)
        assert received == [], f"alpha delivered garbage: {received}"

        assert "beta" in alpha.links, "the battery killed alpha's session"
        assert not alpha.links["beta"].pump.done(), \
            "alpha's reader task died on a garbage inner message"
        assert beta.send("alpha", {"reverse": "ok"})
        assert await until(lambda: received), "alpha stopped delivering"
        assert received == [{"reverse": "ok"}]
    run_async(body())
