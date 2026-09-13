"""BoneMesh v3 distance-vector routing (protocol.md §5/§6).

A table of direct neighbours (EWMA-smoothed link latency) and learned routes
(destination -> next hop, path cost in ms), plus a bounded dedup set for relayed
messages. Wire-compatible with every other reference router.

Poison sentinel: every implementation now advertises exactly ``1000000000`` and
treats any advertised cost ``>= 1000000000`` as unreachable, both pinned by
protocol.md section 0. Four ports used to emit 2^63-1 and interoperated only by
luck of the tolerant threshold; this port always emitted the smaller value, which
no JSON parser can mangle.
"""

from __future__ import annotations

import math

UNREACHABLE = 1_000_000_000
POISON_THRESHOLD = 1_000_000_000
ALPHA = 0.2


class Ewma:
    def __init__(self) -> None:
        self.value = 0.0
        self.has = False

    def observe(self, sample: float) -> None:
        if not self.has:
            self.value = float(sample)
            self.has = True
        else:
            self.value = ALPHA * sample + (1 - ALPHA) * self.value

    def millis(self) -> int:
        # Half away from zero (protocol.md section 5), not Python's round(), which
        # is banker's rounding: round(2.5) is 2 here and 3 in the other six. This
        # was dismissed as a local ranking input, but the rounded value is exactly
        # what disco.routes puts on the wire, so two nodes advertised costs
        # differing by 1 ms for the same measured link. Latency is non-negative,
        # so floor(x + 0.5) is half-away-from-zero.
        return math.floor(self.value + 0.5) if self.has else UNREACHABLE


def sat_sum(a: int, b: int) -> int:
    if a >= POISON_THRESHOLD or b >= POISON_THRESHOLD:
        return UNREACHABLE
    total = a + b
    return UNREACHABLE if total >= POISON_THRESHOLD else total


class Table:
    def __init__(self, self_label: str) -> None:
        self.self_label = self_label.lower()
        self.neighbors: dict[str, Ewma] = {}
        self.routes: dict[str, dict] = {}  # dest -> {"via": label, "cost": int}

    def observe_neighbor(self, label: str, rtt_millis: float) -> None:
        k = label.lower()
        e = self.neighbors.get(k)
        if e is None:
            e = Ewma()
            self.neighbors[k] = e
        e.observe(rtt_millis)

    def remove_neighbor(self, label: str) -> None:
        k = label.lower()
        self.neighbors.pop(k, None)
        for dest in [d for d, r in self.routes.items() if r["via"] == k]:
            del self.routes[dest]

    def learn_route(self, dest: str, via: str, advertised_cost: int) -> None:
        d = dest.lower()
        v = via.lower()
        if d == self.self_label or d == v:
            return
        if v not in self.neighbors:
            return
        # Never shadow a direct neighbour with a learned route: the direct session
        # is always preferable, and letting a route win here was a real
        # convergence defect (docs/architecture.md §4).
        if d in self.neighbors:
            return
        if advertised_cost >= POISON_THRESHOLD:
            r = self.routes.get(d)
            if r and r["via"] == v:
                del self.routes[d]
            return
        cost = sat_sum(advertised_cost, self._neighbor_latency(v))
        r = self.routes.get(d)
        if r is None or r["via"] == v or cost < r["cost"]:
            self.routes[d] = {"via": v, "cost": cost}

    def next_hop(self, dest: str) -> str | None:
        d = dest.lower()
        if d in self.neighbors:
            return d  # a direct neighbour is its own next hop
        r = self.routes.get(d)
        return r["via"] if r else None

    def advertise_to(self, to_neighbor: str) -> dict:
        to = to_neighbor.lower()
        m: dict[str, int] = {}
        for label, e in self.neighbors.items():
            if label != to:
                m[label] = e.millis()
        for dest, r in self.routes.items():
            m[dest] = UNREACHABLE if r["via"] == to else r["cost"]
        m.pop(self.self_label, None)
        return m

    def route_table(self) -> dict:
        return {dest: r["via"] for dest, r in self.routes.items()}

    def _neighbor_latency(self, k: str) -> int:
        e = self.neighbors.get(k)
        return e.millis() if e else UNREACHABLE


class Dedup:
    """A bounded set of recently seen keys (message id + chunk index).

    Used to drop duplicate and looped relay traffic.
    """

    def __init__(self, cap: int) -> None:
        self.cap = cap
        self.seen: set[str] = set()
        self.order: list[str] = []

    def saw_before(self, key: str) -> bool:
        if key in self.seen:
            return True
        self.seen.add(key)
        self.order.append(key)
        if len(self.order) > self.cap:
            self.seen.discard(self.order.pop(0))
        return False
