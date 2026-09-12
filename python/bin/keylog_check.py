#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["bonemesh"]
#
# [tool.uv.sources]
# bonemesh = { path = "..", editable = true }
# ///
"""Reads the shared key-log vector (spec/corpus/keylog.json) and confirms this
implementation can open a key-logged capture.

security.md §8 pins one implementation-neutral key-log format precisely so that a
single inspector reads a log written by a node in any language. That claim needs
every implementation to agree on the format in BOTH directions: it is not enough to
emit lines that your own reader accepts. This checks the reading half against a
committed capture that the Java reference produced -- parse the key-log labels,
pick each frame's direction and epoch key, open it, and reproduce the expected
inner message.

The writing half is covered by each port's own key-log tests and, cross-language and
live, by interop tier 10's key-log scenario.

Invoked by interop/check-keylog-python.sh.
"""

import json
import re
import sys

from bonemesh.transport import open_ciphertext

LABEL = re.compile(r"^BMX3_(I2R|R2I)_TRAFFIC_(\d+)$")


def parse_keylog(lines: list[str]) -> dict[tuple[str, int], bytes]:
    """(direction, epoch) -> key. '#' lines are comments; unknown labels are
    ignored rather than fatal, so a future label shape is not a breaking change."""
    keys: dict[tuple[str, int], bytes] = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 3:
            continue
        m = LABEL.match(parts[0])
        if not m:
            continue
        try:
            key = bytes.fromhex(parts[2])
        except ValueError:
            continue
        if len(key) != 32:
            continue
        keys[(m.group(1).lower(), int(m.group(2)))] = key
    return keys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: keylog_check <keylog.json>", file=sys.stderr)
        return 2
    with open(sys.argv[1], encoding="utf-8") as fh:
        doc = json.load(fh)

    capture = doc.get("capture") or []
    expected = doc.get("expected") or []
    if not capture or len(capture) != len(expected):
        print(f"vector malformed: {len(capture)} capture, {len(expected)} expected",
              file=sys.stderr)
        return 1

    keys = parse_keylog(doc.get("keylog") or [])
    if not keys:
        print("no usable key-log entries in the vector", file=sys.stderr)
        return 1

    import base64
    failures = 0
    for i, (frame, want) in enumerate(zip(capture, expected)):
        direction = frame["dir"]
        seq = int(frame["frame"]["seq"])
        ct = base64.b64decode(frame["frame"]["ct"], validate=True)
        key = keys.get((direction, int(want["epoch"])))
        if key is None:
            print(f"FAIL frame {i}: no key for {direction} epoch {want['epoch']}")
            failures += 1
            continue
        pt = open_ciphertext(key, seq, ct)
        if pt is None:
            print(f"FAIL frame {i}: the logged {direction} key did not open it")
            failures += 1
            continue
        got = json.loads(pt.decode("utf-8"))
        # Compare structurally, not as text: key order is not part of the contract.
        if got == want["inner"]:
            print(f"PASS frame {i} ({direction} seq {seq})")
        else:
            print(f"FAIL frame {i}\n  got:  {json.dumps(got, sort_keys=True)}"
                  f"\n  want: {json.dumps(want['inner'], sort_keys=True)}")
            failures += 1

    # Self-test the oracle: a ciphertext no key seals must be refused, or a
    # checker that reported success for everything would look identical to this one.
    bogus = open_ciphertext(next(iter(keys.values())), 0, bytes(32))
    if bogus is not None:
        print("FAIL self-test: an unopenable frame was accepted")
        failures += 1
    else:
        print("PASS self-test: an unopenable frame is refused")

    if failures:
        print(f"{failures} key-log frame(s) failed", file=sys.stderr)
        return 1
    print("every captured frame opens with its logged key and reproduces the vector")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
