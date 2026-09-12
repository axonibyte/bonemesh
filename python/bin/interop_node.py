#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["bonemesh"]
#
# [tool.uv.sources]
# bonemesh = { path = "..", editable = true }
# ///
"""The Python driver for the language-agnostic interop harness (interop/).

Implements the neutral driver contract (keygen / listen / connect / mesh, plus
caps) over shared, implementation-independent key and certificate files, so the
harness pairs it with any other driver. The node private key is stored as the
32-byte FIPS ML-DSA seed in base64; it never crosses a node boundary, so its
format is this driver's own business (the JS driver stores PKCS#8 DER, PHP stores
base64 PEM).
"""

import asyncio
import base64
import json
import sys
import time

from bonemesh import cert as certmod
from bonemesh import crypto
from bonemesh.node import Config, Node

# Feature tokens the harness health-probes to gate tier-10 scenarios. No
# "capture": teeing raw wire frames is Go-only by decision #18.
CAPS = "ack nak rekey idle probe-death dial-tiebreak keylog sessions acks"


def parse_flags(args: list[str]) -> dict:
    """Strict --key value pairs walked two at a time, as every driver does.

    A lone trailing --flag is ignored, unknown flags are accepted, last wins.
    """
    out = {}
    i = 0
    while i + 1 < len(args):
        if args[i].startswith("--"):
            out[args[i][2:]] = args[i + 1]
        i += 2
    return out


def read_text(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def append_json_line(path: str, obj) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n")


def write_json(path: str, obj) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, separators=(",", ":"), ensure_ascii=False))


def keygen(f: dict) -> int:
    pub, priv = crypto.mldsa65_generate()
    with open(f["id-pub"], "w", encoding="ascii") as fh:
        fh.write(base64.b64encode(pub).decode("ascii"))
    with open(f["id-priv"], "w", encoding="ascii") as fh:
        fh.write(base64.b64encode(priv).decode("ascii"))
    return 0


def config(f: dict) -> Config:
    root_public = base64.b64decode(read_text(f["root-pub"]).strip())
    id_private = base64.b64decode(read_text(f["id-priv"]).strip())
    cert = json.loads(read_text(f["cert"]))
    # The node's own label comes from its certificate, never from a flag.
    return Config(cert["label"], f["mesh"], root_public, cert, id_private)


def seconds(f: dict) -> float:
    return float(f.get("seconds", 10))


def observe(node: Node, f: dict) -> None:
    """Optional --acks: append each received ack/nak inner as one JSON line."""
    if f.get("acks"):
        node.on_ack(lambda a: append_json_line(f["acks"], a))


def dump_sessions(node: Node, f: dict) -> None:
    if f.get("sessions"):
        write_json(f["sessions"], node.session_info())


async def listen(f: dict) -> int:
    node = await Node.start(config(f), int(f["port"]))
    observe(node, f)
    if f.get("out"):
        node.on_message(lambda payload: append_json_line(f["out"], payload))
    deadline = time.monotonic() + seconds(f)
    while time.monotonic() < deadline:
        dump_sessions(node, f)
        await asyncio.sleep(0.2)
    node.kill()
    return 0


async def connect(f: dict) -> int:
    node = await Node.start(config(f), 0)
    observe(node, f)
    try:
        await node.connect(f["host"], int(f["port"]))
    except Exception as e:
        print(f"connect: {e}", file=sys.stderr)
        node.kill()
        return 1
    payload = json.loads(read_text(f["message"]))
    deadline = time.monotonic() + seconds(f)
    while time.monotonic() < deadline:
        if node.send(f["to"], payload):
            break
        await asyncio.sleep(0.2)
    # Stay up briefly so acks/naks and the session dump can be observed.
    end = time.monotonic() + 1.5
    while time.monotonic() < end:
        dump_sessions(node, f)
        await asyncio.sleep(0.2)
    node.kill()
    return 0


async def mesh(f: dict) -> int:
    """The multi-link mode for the convergence tier.

    Dials several --peers (host:port,host:port), optionally logs delivered payloads
    (--out), repeatedly sends toward a routed destination (--send-to with
    --message), and periodically dumps the routing table (--routes).
    """
    node = await Node.start(config(f), int(f.get("port", 0)))
    observe(node, f)
    if f.get("out"):
        node.on_message(lambda payload: append_json_line(f["out"], payload))
    for peer in [p for p in (f.get("peers") or "").split(",") if p]:
        host, _, port = peer.rpartition(":")
        try:
            await node.connect(host, int(port))
        except Exception as e:
            print(f"mesh: dial {peer} failed: {e}", file=sys.stderr)
    payload = json.loads(read_text(f["message"])) if f.get("message") else None
    deadline = time.monotonic() + seconds(f)
    while time.monotonic() < deadline:
        if f.get("send-to") and payload is not None:
            node.send(f["send-to"], payload)
        if f.get("routes"):
            write_json(f["routes"], node.route_table())
        dump_sessions(node, f)
        await asyncio.sleep(0.5)
    node.kill()
    return 0


def main() -> int:
    argv = sys.argv[1:]
    if not argv:
        print("usage: interop_node <keygen|listen|connect|mesh|caps> [--flag value ...]",
              file=sys.stderr)
        return 2
    mode, rest = argv[0], argv[1:]
    if mode == "caps":
        print(CAPS)
        return 0
    f = parse_flags(rest)
    if mode == "keygen":
        return keygen(f)
    if mode == "listen":
        return asyncio.run(listen(f))
    if mode == "connect":
        return asyncio.run(connect(f))
    if mode == "mesh":
        return asyncio.run(mesh(f))
    print("usage: interop_node <keygen|listen|connect|mesh|caps> [--flag value ...]",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
