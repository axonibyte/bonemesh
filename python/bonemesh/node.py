"""A BoneMesh v3 mesh node (protocol.md §3, §5) over TCP.

One authenticated, encrypted session per neighbour, each served by an async frame
reader. It routes -- distance-vector discovery over a 1 s heartbeat (probe/echo
for link latency, disco for route advertisement with poisoned reverse) -- relays
data toward a next hop with TTL, and delivers payloads addressed to itself,
deduping by message id. Wire-compatible with the Java, Go, Rust, JS, PHP and
Elixir implementations.

Built on ``asyncio``, which is the closest structural match to the JS reference:
a single event loop means there is no shared-state race to guard (contrast the
Java node's synchronized routing tables), because each link's seal/open runs to
completion without interleaving.
"""

from __future__ import annotations

import asyncio
import base64
import json
import sys
import time

from bonemesh import message
from bonemesh.frame import HANDSHAKE_CAP, TRANSPORT_CAP, classify, encode
from bonemesh.handshake import Handshake
from bonemesh.routing import Dedup, Table
from bonemesh.transport import Transport, TransportError
from bonemesh.tunables import load_tunables

DEDUP_WINDOW = 4096
HEARTBEAT_S = 1.0
RETRY_QUEUE_MAX = 64


def _now() -> int:
    """Unix seconds -- certificate validity."""
    return int(time.time())


def _now_ms() -> int:
    """Unix milliseconds -- probes, heartbeats and every tunable."""
    return int(time.time() * 1000)


def _th_prefix(session) -> str:
    """The first 16 hex chars of a session's transcript hash.

    A compact session label for the harness's ``--sessions`` dump; both ends of a
    session agree on it. The key log carries the full hash, not this prefix.
    """
    return session.h.hex()[:16] if session is not None and session.h else ""


class FrameError(Exception):
    """A frame was rejected at the framing layer (protocol.md §2)."""


class Config:
    """Everything a node needs to prove who it is."""

    __slots__ = ("label", "mesh", "root_public", "cert", "id_private")

    def __init__(self, label: str, mesh: str, root_public: bytes, cert: dict,
                 id_private: bytes) -> None:
        self.label = label
        self.mesh = mesh
        self.root_public = root_public
        self.cert = cert
        self.id_private = id_private


class _Link:
    """One authenticated session with a neighbour."""

    __slots__ = ("reader", "writer", "transport", "initiator", "established_at",
                 "last_inbound", "last_data", "th", "rekey_hs", "rekey_mid",
                 "rekey_started_at", "rekey_session", "rekey_epoch", "pump")

    def __init__(self, reader, writer, transport, initiator, th) -> None:
        now = _now_ms()
        self.reader = reader
        self.writer = writer
        self.transport = transport
        # Whether this node dialled the connection (protocol.md §3 -- the
        # simultaneous-dial tiebreak needs to know who initiated each competing
        # session). last_inbound/last_data feed the liveness and idle checks;
        # probe/echo/disco never count as data activity.
        self.initiator = initiator
        self.established_at = now
        self.last_inbound = now
        self.last_data = now
        self.th = th
        self.rekey_hs = None
        self.rekey_mid = None
        self.rekey_started_at = 0
        self.rekey_session = None
        self.rekey_epoch = 0
        self.pump = None


async def _read_frame(reader: asyncio.StreamReader, cap: int) -> dict:
    """Read exactly one frame, raising FrameError on any framing fault."""
    try:
        line = await reader.readuntil(b"\n")
    except asyncio.LimitOverrunError as e:
        raise FrameError("oversize") from e
    except (asyncio.IncompleteReadError, ConnectionError, OSError) as e:
        raise FrameError("connection closed") from e
    obj, reason = classify(line, cap)
    if reason:
        raise FrameError(reason)
    return obj


class Node:
    def __init__(self, config: Config) -> None:
        self.cfg = config
        self.tun = load_tunables()
        self.links: dict[str, _Link] = {}
        self.listeners: list = []
        self.ack_listeners: list = []
        # F2: per-destination bounded queue of origin data messages awaiting retry.
        self.pending: dict[str, list] = {}
        self.server: asyncio.Server | None = None
        self.table = Table(config.label)
        self.dedup = Dedup(DEDUP_WINDOW)
        self._hb_task: asyncio.Task | None = None
        self._tasks: set[asyncio.Task] = set()
        # Connections still inside the handshake, i.e. accepted but not yet a
        # registered link. server.close() stops accepting but does NOT close
        # already-accepted sockets, so without this a node killed mid-handshake
        # leaves the socket open until the peer's probe timeout notices.
        self._handshaking: set = set()
        self._keylog_warned = False

    # --- lifecycle ---------------------------------------------------------

    @classmethod
    async def start(cls, config: Config, port: int) -> "Node":
        node = cls(config)
        node.server = await asyncio.start_server(
            node._respond, host="0.0.0.0", port=port, limit=TRANSPORT_CAP * 2
        )
        node._hb_task = node._spawn(node._heartbeat())
        return node

    def port(self) -> int:
        return self.server.sockets[0].getsockname()[1]

    def kill(self) -> None:
        if self._hb_task:
            self._hb_task.cancel()
        for t in list(self._tasks):
            t.cancel()
        if self.server:
            self.server.close()
        for writer in list(self._handshaking):
            try:
                writer.close()
            except Exception:
                pass
        self._handshaking.clear()
        for link in list(self.links.values()):
            self._close(link)
        self.links.clear()

    def _spawn(self, coro) -> asyncio.Task:
        t = asyncio.ensure_future(coro)
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)
        return t

    @staticmethod
    def _close(link: _Link) -> None:
        try:
            link.writer.close()
        except Exception:
            pass

    # --- heartbeat ---------------------------------------------------------

    async def _heartbeat(self) -> None:
        """1 s maintenance: probe and advertise on each link, or tear it down."""
        while True:
            await asyncio.sleep(HEARTBEAT_S)
            now = _now_ms()
            for label, link in list(self.links.items()):
                if self.sweep_link(now, label, link):
                    self.maybe_rekey(link, now)
            self.drain_retries(now)

    def sweep_link(self, now: int, peer: str, link: _Link) -> bool:
        """Once-per-heartbeat maintenance for one link.

        Tears it down if it is probe-timeout dead (F3) or data-idle past the idle
        timeout (F4, disabled at ``idle_ms == 0``); otherwise sends a probe and a
        route advertisement. Returns whether the link survived.
        """
        if now - link.last_inbound > self.tun.probe_timeout_ms:
            self._deregister(peer, link)
            self._close(link)
            return False
        if self.tun.idle_ms > 0 and now - link.last_data > self.tun.idle_ms:
            self._send_to_link(peer, message.bye("idle"))
            self._deregister(peer, link)
            self._close(link)
            return False
        self._send_to_link(peer, message.probe(now))
        self._send_to_link(peer, message.disco(self.table.advertise_to(peer)))
        return True

    def maybe_rekey(self, link: _Link, now_millis: int) -> None:
        """F5: drive the initiator side of a periodic rekey.

        Abandons a stalled pre-swap handshake at the rekey timeout, keeping the
        old keys -- the safe degrade against a peer that ignores rekey. Otherwise,
        on the session initiator only, starts a fresh BMX once the frame count or
        session age crosses the threshold.
        """
        if link.rekey_hs is not None:
            if now_millis - link.rekey_started_at > self.tun.rekey_timeout_ms:
                link.rekey_hs = None
            return
        if link.rekey_session is not None:
            return  # initiator swapped send, awaiting phase 4
        if not link.initiator:
            return
        due = (link.transport.send_seq >= self.tun.rekey_frames
               or link.transport.receive_seq >= self.tun.rekey_frames
               or now_millis - link.established_at >= self.tun.rekey_ms)
        if not due:
            return
        hs = Handshake.initiator(self.cfg.mesh, self.cfg.root_public, _now(),
                                 self.cfg.cert, self.cfg.id_private)
        mid = message.new_mid()
        self._write_on(link, {"type": "rekey", "mid": mid, "phase": 1,
                              "body": base64.b64encode(hs.write_message1()).decode("ascii")})
        link.rekey_hs = hs
        link.rekey_mid = mid
        link.rekey_started_at = now_millis

    def drain_retries(self, now: int) -> None:
        """F2: re-attempt due pending sends once per heartbeat.

        A landed message is dropped, a still-stuck one backs off (the delay
        doubles to the cap), and one past its lifetime is dropped and reported to
        the origin's ack listeners as a synthesized ``nak{reason:"expired"}`` --
        which never appears on the wire.
        """
        for dest, queue in list(self.pending.items()):
            keep = []
            for p in queue:
                if now < p["next_at"]:
                    keep.append(p)
                    continue
                nh = self.table.next_hop(p["inner"]["to"])
                delivered = self._send_to_link(nh, p["inner"]) if nh else False
                if delivered:
                    continue
                if now - p["enqueued_at"] > self.tun.retry_max_ms:
                    self._emit_to_ack_listeners({
                        "type": "nak", "mid": p["inner"]["mid"], "hop": self.cfg.label,
                        "reason": "expired", "to": self.cfg.label, "from": self.cfg.label,
                        "ttl": message.DEFAULT_TTL,
                    })
                    continue
                p["delay"] = min(p["delay"] * 2, self.tun.retry_cap_ms)
                p["next_at"] = now + p["delay"]
                keep.append(p)
            if keep:
                self.pending[dest] = keep
            else:
                del self.pending[dest]

    def _enqueue_retry(self, inner: dict) -> None:
        """Queue an origin data message for retry, bounded per destination.

        A no-op when retry is disabled (``retry_max_ms == 0``).
        """
        if self.tun.retry_max_ms <= 0:
            return
        dest = str(inner["to"]).lower()
        q = self.pending.setdefault(dest, [])
        if len(q) >= RETRY_QUEUE_MAX:
            return
        now = _now_ms()
        q.append({"inner": inner, "enqueued_at": now,
                  "next_at": now + self.tun.retry_base_ms, "delay": self.tun.retry_base_ms})

    # --- public API --------------------------------------------------------

    def route_table(self) -> dict:
        """A snapshot of learned destinations to their next hop."""
        return self.table.route_table()

    def on_message(self, cb) -> None:
        """Register a callback invoked with each delivered application payload."""
        self.listeners.append(cb)

    def on_ack(self, cb) -> None:
        """Register a callback invoked with each ack/nak addressed to this node."""
        self.ack_listeners.append(cb)

    def session_info(self) -> dict:
        """Per-neighbour rekey epoch and transcript-hash label.

        The observability the interop harness dumps via ``--sessions``; both ends
        of a session agree on ``th``.
        """
        return {peer: {"epoch": link.rekey_epoch, "th": link.th}
                for peer, link in self.links.items()}

    async def connect(self, host: str, port: int) -> str:
        """Dial a peer and complete the BMX handshake. Returns its label."""
        reader, writer = await asyncio.open_connection(host, port, limit=TRANSPORT_CAP * 2)
        # A dial that fails anywhere past this point must close the socket before
        # it propagates. Without this a rejected handshake leaks a file
        # descriptor per attempt -- and tier 9's nemesis churn dials with a
        # foreign-root certificate over and over, so the leak would be unbounded.
        try:
            hs = Handshake.initiator(self.cfg.mesh, self.cfg.root_public, _now(),
                                     self.cfg.cert, self.cfg.id_private)
            writer.write(hs.write_message1())
            await writer.drain()
            m2 = await _read_frame(reader, HANDSHAKE_CAP)
            writer.write(hs.read_message2_write_message3(m2))
            await writer.drain()
        except BaseException:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            raise
        peer = hs.session.peer_cert["label"]
        if self._register(peer, reader, writer, hs.session, True):
            self._write_keylog(0, True, hs.session)
        return peer

    def send(self, to: str, payload) -> bool:
        """Route an application payload. True if handed to a next hop."""
        return self.send_mid(to, payload)[1]

    def send_mid(self, to: str, payload) -> tuple[str, bool]:
        """Send, also returning the message id so a caller can correlate the
        ack/nak delivered to ``on_ack`` (protocol.md §7)."""
        return self.send_with_ttl(to, payload, message.DEFAULT_TTL)

    def send_with_ttl(self, to: str, payload, ttl: int) -> tuple[str, bool]:
        """send_mid with an explicit initial TTL, so a test can force a relay to
        exhaust the hop limit and emit a NAK."""
        mid = message.new_mid()
        msg = message.data(mid, self.cfg.label, to, ttl, payload)
        nh = self.table.next_hop(to)
        if not nh or not self._send_to_link(nh, msg):
            self._enqueue_retry(msg)  # F2: retry when a route or link appears
            return mid, False
        return mid, True

    def broadcast(self, payload) -> int:
        """Send to every reachable label except this node. Returns the count."""
        return sum(1 for label in self.table.reachable() if self.send(label, payload))

    # --- wire --------------------------------------------------------------

    def _write_on(self, link: _Link, inner: dict) -> None:
        """Seal and write directly on a link.

        Rekey uses this so seal-then-swap is one step with nothing interleaved.
        """
        if inner.get("type") == "data":
            link.last_data = _now_ms()
        link.writer.write(encode(link.transport.seal(inner)))

    def _send_to_link(self, label: str, inner: dict) -> bool:
        link = self.links.get(label.lower())
        if link is None:
            return False
        if inner.get("type") == "data":
            link.last_data = _now_ms()
        try:
            link.writer.write(encode(link.transport.seal(inner)))
            return True
        except Exception:
            return False

    async def _respond(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        hs = Handshake.responder(self.cfg.mesh, self.cfg.root_public, _now(),
                                 self.cfg.cert, self.cfg.id_private)
        self._handshaking.add(writer)
        try:
            m1 = await _read_frame(reader, HANDSHAKE_CAP)
            writer.write(hs.read_message1_write_message2(m1))
            await writer.drain()
            m3 = await _read_frame(reader, HANDSHAKE_CAP)
            hs.read_message3(m3)
        except Exception:
            # Any handshake fault closes the connection with no reply and no
            # partial state (protocol.md §2). Deliberately broad: a malformed
            # peer must never take the listener down, which is what tier 5 and
            # tier 7 exist to prove.
            try:
                writer.close()
            except Exception:
                pass
            return
        finally:
            self._handshaking.discard(writer)
        peer = hs.session.peer_cert["label"]
        if self._register(peer, reader, writer, hs.session, False):
            self._write_keylog(0, False, hs.session)

    def _register(self, peer: str, reader, writer, session, initiator: bool) -> bool:
        transport = Transport(session.send_key, session.receive_key)
        link = _Link(reader, writer, transport, initiator, _th_prefix(session))
        k = peer.lower()
        prev = self.links.get(k)
        # F1 simultaneous-dial tiebreak (protocol.md §3): if an existing link was
        # initiated by the opposite side this is a genuine dial collision -- both
        # ends deterministically keep the session initiated by the lower-labelled
        # node, so the pair converges on one session. Same-initiator is a
        # reconnect (last writer wins).
        if prev is not None and prev.initiator != initiator:
            self_wins = self.cfg.label.lower() < peer.lower()
            if initiator != self_wins:
                self._close(link)  # this new link lost; keep the existing one
                return False
        self.links[k] = link
        if prev is not None and prev is not link:
            # Displaced an existing link (reconnect, or a collision the new link
            # won): close it. Its deregister is identity-guarded, so its death
            # cannot withdraw this new link's routes.
            self._close(prev)
        self.table.observe_neighbor(peer, 1)  # optimistic seed so it is routable
        link.pump = self._spawn(self._pump(peer, link))
        return True

    async def _pump(self, peer: str, link: _Link) -> None:
        """Read transport carriers for one link until it closes."""
        try:
            while True:
                try:
                    line = await link.reader.readuntil(b"\n")
                except (asyncio.LimitOverrunError, asyncio.IncompleteReadError,
                        ConnectionError, OSError):
                    return
                obj, reason = classify(line, TRANSPORT_CAP)
                if reason is not None:
                    # A framing fault closes the connection with no partial
                    # recovery (protocol.md §2).
                    return
                try:
                    inner = link.transport.open(obj)
                except TransportError:
                    # An AEAD or ordering fault drops the frame but keeps the
                    # link, matching the other implementations -- this is the
                    # path tier 7's corrupted-carrier strategy exercises.
                    continue
                link.last_inbound = _now_ms()
                if inner.get("type") == "data":
                    link.last_data = _now_ms()
                if inner.get("type") == "bye":
                    return  # peer is closing gracefully
                self._handle_inner(peer, link, inner)
        except asyncio.CancelledError:
            raise
        finally:
            self._deregister(peer, link)
            self._close(link)

    def _deregister(self, peer: str, link: _Link) -> None:
        """Withdraw a dropped link's routes, but only if it is still current.

        A reconnect may have replaced it, and the stale link's death must not
        withdraw the live link's routes.
        """
        k = peer.lower()
        if self.links.get(k) is link:
            del self.links[k]
            self.table.remove_neighbor(peer)

    # --- inner-message dispatch -------------------------------------------

    def _handle_inner(self, peer: str, link: _Link, msg: dict) -> None:
        t = msg.get("type")
        if t == "probe":
            self._send_to_link(peer, message.echo(msg.get("token")))
        elif t == "echo":
            token = msg.get("token")
            if isinstance(token, int) and not isinstance(token, bool):
                self.table.observe_neighbor(peer, max(0, _now_ms() - token))
        elif t == "disco":
            routes = msg.get("routes")
            if isinstance(routes, dict):
                for dest, cost in routes.items():
                    if isinstance(cost, (int, float)) and not isinstance(cost, bool):
                        self.table.learn_route(dest, peer, cost)
        elif t == "data":
            self._handle_data(msg)
        elif t == "ack":
            self._handle_control(msg, "a:")
        elif t == "nak":
            self._handle_control(msg, "n:")
        elif t == "rekey":
            self._handle_rekey(link, msg)
        # Unknown inner types are ignored (protocol.md §8).

    def _handle_rekey(self, link: _Link, msg: dict) -> None:
        """F5: advance the tunneled-BMX rekey state machine for one link.

        The BMX messages ride inside transport frames, so they arrive through the
        normal reader with no raw-stream race; each side swaps its send key
        immediately after sealing its last old-key frame and its receive key
        immediately after opening the peer's (protocol.md §5 / security.md §6).
        """
        def decode_frame(b64: str) -> dict:
            return json.loads(base64.b64decode(b64).decode("utf-8"))

        phase = msg.get("phase")
        if phase == 1:  # responder: accept the fresh bmx1, reply bmx2
            hs = Handshake.responder(self.cfg.mesh, self.cfg.root_public, _now(),
                                     self.cfg.cert, self.cfg.id_private)
            try:
                m2 = hs.read_message1_write_message2(decode_frame(msg["body"]))
            except Exception:
                return
            link.rekey_hs = hs
            link.rekey_mid = msg.get("mid")
            link.rekey_started_at = _now_ms()
            self._write_on(link, {"type": "rekey", "mid": msg.get("mid"), "phase": 2,
                                  "body": base64.b64encode(m2).decode("ascii")})
        elif phase == 2:  # initiator: finish with bmx3, then swap its send key
            if link.rekey_hs is None:
                return
            try:
                m3 = link.rekey_hs.read_message2_write_message3(decode_frame(msg["body"]))
            except Exception:
                link.rekey_hs = None
                return
            sess = link.rekey_hs.session
            self._write_on(link, {"type": "rekey", "mid": msg.get("mid"), "phase": 3,
                                  "body": base64.b64encode(m3).decode("ascii")})
            link.transport.swap_send(sess.send_key)  # last old-key frame sent above
            link.rekey_session = sess
            link.rekey_hs = None
        elif phase == 3:  # responder: verify bmx3, swap receive, phase 4, swap send
            if link.rekey_hs is None:
                return
            try:
                link.rekey_hs.read_message3(decode_frame(msg["body"]))
            except Exception:
                link.rekey_hs = None
                return
            sess = link.rekey_hs.session
            link.transport.swap_receive(sess.receive_key)  # phase 3 was the last old inbound
            self._write_on(link, {"type": "rekey", "mid": msg.get("mid"), "phase": 4})
            link.transport.swap_send(sess.send_key)
            link.rekey_hs = None
            link.rekey_epoch += 1
            link.th = _th_prefix(sess)
            self._write_keylog(link.rekey_epoch, link.initiator, sess)
        elif phase == 4:  # initiator: swap receive; rekey complete
            if link.rekey_session is None:
                return
            rs = link.rekey_session
            link.transport.swap_receive(rs.receive_key)
            link.rekey_session = None
            link.rekey_epoch += 1
            link.th = _th_prefix(rs)
            self._write_keylog(link.rekey_epoch, link.initiator, rs)

    def _handle_data(self, msg: dict) -> None:
        chunk = msg.get("chunk")
        chunk_idx = -1
        if isinstance(chunk, dict) and isinstance(chunk.get("i"), int):
            chunk_idx = chunk["i"]
        if self.dedup.saw_before(f"d:{msg.get('mid')}:{chunk_idx}"):
            return
        frm = str(msg.get("from") or "")
        me = self.cfg.label.lower()
        if str(msg.get("to") or "").lower() == me:
            for cb in self.listeners:
                try:
                    cb(msg.get("payload"))
                except Exception:
                    pass  # a listener's errors are its own
            # F6: acknowledge receipt back toward the origin.
            if frm and frm.lower() != me:
                self._route_control(
                    message.ack_to(msg.get("mid"), self.cfg.label, frm, message.DEFAULT_TTL))
            return
        ttl = msg.get("ttl")
        ttl = (ttl if isinstance(ttl, int) and not isinstance(ttl, bool) else 0) - 1
        if ttl <= 0:
            # F6/D4: the relay that dropped it names itself as the failing hop.
            self._emit_nak(msg.get("mid"), frm, "ttl")
            return
        nh = self.table.next_hop(str(msg.get("to") or ""))
        if not nh:
            self._emit_nak(msg.get("mid"), frm, "no-route")
            return
        onward = dict(msg)
        onward["ttl"] = ttl
        if not self._send_to_link(nh, onward):
            # The next-hop link died between routing and writing; name it so the
            # origin learns which hop broke (F2/D4).
            self._emit_nak_hop(msg.get("mid"), frm, nh, "link-dead")

    def _handle_control(self, msg: dict, prefix: str) -> None:
        """Relay or deliver an ack/nak, routed back toward the origin like data.

        A type-prefixed dedup key keeps a relayed ack from colliding with the data
        it answers (same mid). ack/nak are never themselves ack'd or nak'd.
        """
        if self.dedup.saw_before(f"{prefix}{msg.get('mid')}"):
            return
        if str(msg.get("to") or "").lower() == self.cfg.label.lower():
            self._emit_to_ack_listeners(msg)
            return
        ttl = msg.get("ttl")
        ttl = (ttl if isinstance(ttl, int) and not isinstance(ttl, bool) else 0) - 1
        if ttl <= 0:
            return  # drop silently; no nak-of-nak
        nh = self.table.next_hop(str(msg.get("to") or ""))
        if not nh:
            return
        onward = dict(msg)
        onward["ttl"] = ttl
        self._send_to_link(nh, onward)

    def _emit_to_ack_listeners(self, msg: dict) -> None:
        for cb in self.ack_listeners:
            try:
                cb(msg)
            except Exception:
                pass  # a listener's errors are its own

    def _emit_nak(self, mid, origin: str, reason: str) -> None:
        """Send a NAK back toward the origin naming this node as the failing hop."""
        self._emit_nak_hop(mid, origin, self.cfg.label, reason)

    def _emit_nak_hop(self, mid, origin: str, hop: str, reason: str) -> None:
        """Send a NAK naming an explicit failing hop.

        This node for a local drop, the next-hop label for a dead onward link.
        Best-effort: dropped if it cannot be routed, with no recursion.
        """
        if not origin or origin.lower() == self.cfg.label.lower():
            return
        self._route_control(
            message.nak(mid, self.cfg.label, origin, hop, reason, message.DEFAULT_TTL))

    def _route_control(self, msg: dict) -> None:
        """Send a freshly built ack/nak toward its destination.

        Dropped silently when there is no route, so a control message never
        produces a control-of-control.
        """
        nh = self.table.next_hop(str(msg.get("to") or ""))
        if not nh:
            return
        self._send_to_link(nh, msg)

    # --- key log -----------------------------------------------------------

    def _write_keylog(self, epoch: int, initiator: bool, session) -> None:
        """Append this session's directional transport keys to BONEMESH_KEYLOG.

        The pinned cross-language format (security.md §8)::

            BMX3_I2R_TRAFFIC_<epoch> <hex transcript-hash> <hex key>
            BMX3_R2I_TRAFFIC_<epoch> <hex transcript-hash> <hex key>

        A no-op unless the variable is set, and a loud warning on the first write
        because it defeats forward secrecy for anyone holding the file. The
        role-relative send/receive keys are mapped onto the absolute I2R/R2I
        directions so one inspector reads a log written by either end.
        """
        path = self.tun.keylog_path
        if not path or session is None:
            return
        i2r, r2i = session.send_key, session.receive_key
        if not initiator:
            i2r, r2i = session.receive_key, session.send_key
        th = session.h.hex()
        try:
            with open(path, "a", encoding="ascii") as fh:
                for direction, key in (("I2R", i2r), ("R2I", r2i)):
                    fh.write(f"BMX3_{direction}_TRAFFIC_{epoch} {th} {key.hex()}\n")
        except OSError:
            return
        if epoch == 0 and not self._keylog_warned:
            self._keylog_warned = True
            print(
                f"WARNING: BONEMESH_KEYLOG is on; transport keys written to {path}"
                " — forward secrecy is defeated for anyone holding that file",
                file=sys.stderr,
            )
