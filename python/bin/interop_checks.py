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
    interop_checks chunk    <chunk.json>

Prints PASS/FAIL per case and exits non-zero on any mismatch. Invoked by
interop/check-framing-python.sh and interop/check-messages-python.sh.
"""

import base64
import json
import sys

from bonemesh import chunk as chunkmod
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


def run_chunk(path: str) -> int:
    """Checks splitting against the shared corpus (spec/corpus/chunk.json).

    Two things, and the second is the one nothing else can see. First the pinned
    section 0 constants must match this implementation's -- including the three
    (chunk count, in-flight count, timeout) that specsrc deliberately does not
    check, because a substring search for 1024, 256 or 30000 is satisfied by any
    buffer size already in the tree. Second, the segments this implementation
    produces must land on exactly the byte boundaries the corpus pins, which is how
    all seven are shown to cut in the SAME places rather than merely to cut.
    """
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    failures = 0

    mine = {
        "max_segment_bytes": chunkmod.MAX_SEGMENT_BYTES,
        "max_chunks": chunkmod.MAX_CHUNKS,
        "max_reassembly_buffer": chunkmod.MAX_REASSEMBLY_BUFFER,
        "max_concurrent_reassemblies": chunkmod.MAX_CONCURRENT_REASSEMBLIES,
        "reassembly_timeout_millis": chunkmod.REASSEMBLY_TIMEOUT_MILLIS,
    }
    pinned = doc.get("constants") or {}
    if not pinned:
        print("corpus declares no chunk constants", file=sys.stderr)
        return 1
    for name, want in pinned.items():
        got = mine.get(name)
        ok = got == want
        print(f"{'PASS' if ok else 'FAIL'} constant {name}"
              + ("" if ok else f"  (have {got}, corpus pins {want})"))
        failures += 0 if ok else 1

    cases = doc.get("split_cases") or []
    if not cases:
        print("corpus has no split cases", file=sys.stderr)
        return 1
    mid = doc["mid"]
    for case in cases:
        payload = {case["key"]: case["unit"] * case["times"]}
        msgs = chunkmod.split(mid, "a", "b", 16, payload)
        whole = len(msgs) == 1 and "payload" in msgs[0]
        lengths = [] if whole else [len(m["seg"].encode("utf-8")) for m in msgs]
        ok = whole == case["expect_whole"] and lengths == case["segment_byte_lengths"]
        detail = ""
        if not ok:
            detail = (f"  (whole={whole} want {case['expect_whole']}; "
                      f"lengths={lengths[:8]} want {case['segment_byte_lengths'][:8]})")
        # A round-trip as the second oracle: matching lengths would not catch
        # segments that are the right size and the wrong bytes.
        if ok and not whole:
            rebuilt = json.loads("".join(m["seg"] for m in msgs))
            if rebuilt != payload:
                ok, detail = False, "  (segments did not rebuild the payload)"
        print(f"{'PASS' if ok else 'FAIL'} {case['name']}{detail}")
        failures += 0 if ok else 1

    if failures:
        print(f"{failures} chunk case(s) disagreed", file=sys.stderr)
        return 1
    print("splitting agrees with every pinned constant and cut position")
    return 0


def main() -> int:
    runners = {"framing": run_framing, "messages": run_messages, "chunk": run_chunk}
    if len(sys.argv) != 3 or sys.argv[1] not in runners:
        print("usage: interop_checks <framing|messages|chunk> <corpus.json>", file=sys.stderr)
        return 2
    return runners[sys.argv[1]](sys.argv[2])


if __name__ == "__main__":
    raise SystemExit(main())
