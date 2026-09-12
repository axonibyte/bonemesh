#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["bonemesh"]
#
# [tool.uv.sources]
# bonemesh = { path = "..", editable = true }
# ///
"""Corpus-driven framing and message-schema checks.

    interop_checks framing  <framing.json>
    interop_checks messages <messages.json>

Prints PASS/FAIL per case and exits non-zero on any mismatch. Invoked by
interop/check-framing-python.sh and interop/check-messages-python.sh.
"""

import base64
import json
import sys

from bonemesh.frame import HANDSHAKE_CAP, TRANSPORT_CAP, classify
from bonemesh.message import validate

CAPS = {"handshake": HANDSHAKE_CAP, "transport": TRANSPORT_CAP}


def run_framing(path: str) -> int:
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    failures = 0
    cases = doc.get("cases") or []
    if not cases:
        print("corpus has no framing cases", file=sys.stderr)
        return 1
    for case in cases:
        cap = CAPS[case["kind"]]
        obj, reason = classify(base64.b64decode(case["bytes_b64"]), cap)
        if case["expect"] == "accept":
            ok = obj is not None and reason is None
            detail = f"rejected as {reason}"
        else:
            ok = obj is None and reason == case.get("reason")
            detail = f"got {reason}, want {case.get('reason')}"
        print(f"{'PASS' if ok else 'FAIL'} {case['name']}" + ("" if ok else f"  ({detail})"))
        failures += 0 if ok else 1

    # The runner also generates frames exactly at the cap (accept) and one byte
    # over (reject), from the caps the corpus declares.
    sizes = doc.get("size_cases") or {}
    for kind, cap_key in (("handshake", "handshake_cap"), ("transport", "transport_cap")):
        cap = sizes.get(cap_key)
        if cap is None:
            continue
        if cap != CAPS[kind]:
            print(f"FAIL corpus {kind} cap {cap} disagrees with code {CAPS[kind]}")
            failures += 1
            continue
        filler = b"a" * (cap - len(b'{"p":""}') - 1)
        at_cap = b'{"p":"' + filler + b'"}\n'
        over = b'{"p":"' + filler + b'a"}\n'
        ok = classify(at_cap, cap)[1] is None
        print(f"{'PASS' if ok else 'FAIL'} generated-{kind}-at-cap")
        failures += 0 if ok else 1
        ok = classify(over, cap)[1] == "oversize"
        print(f"{'PASS' if ok else 'FAIL'} generated-{kind}-over-cap")
        failures += 0 if ok else 1

    if failures:
        print(f"{failures} framing case(s) disagreed", file=sys.stderr)
        return 1
    print("frame classifier agrees with every shared case")
    return 0


def run_messages(path: str) -> int:
    with open(path, encoding="utf-8") as fh:
        cases = json.load(fh).get("cases") or []
    if not cases:
        print("corpus has no message cases", file=sys.stderr)
        return 1
    failures = 0
    for case in cases:
        got = validate(case["schema"], case["frame"])
        if case["expect"] == "valid":
            ok = got is None
            detail = f"rejected as {got}"
        else:
            ok = got == case.get("reason")
            detail = f"got {got}, want {case.get('reason')}"
        print(f"{'PASS' if ok else 'FAIL'} {case['name']}" + ("" if ok else f"  ({detail})"))
        failures += 0 if ok else 1
    if failures:
        print(f"{failures} message case(s) disagreed", file=sys.stderr)
        return 1
    print("message validator agrees with every shared case")
    return 0


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in ("framing", "messages"):
        print("usage: interop_checks <framing|messages> <corpus.json>", file=sys.stderr)
        return 2
    return run_framing(sys.argv[2]) if sys.argv[1] == "framing" else run_messages(sys.argv[2])


if __name__ == "__main__":
    raise SystemExit(main())
