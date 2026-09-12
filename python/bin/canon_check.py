#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["bonemesh"]
#
# [tool.uv.sources]
# bonemesh = { path = "..", editable = true }
# ///
"""Reads the shared canon corpus (spec/corpus/canon.json) and confirms this
implementation reproduces every canonical byte string exactly.

Agreement means a certificate signed by one implementation verifies under any
other. Invoked by interop/check-canon-python.sh.
"""

import json
import sys

from bonemesh.canon import canonicalize


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: canon_check <canon.json>", file=sys.stderr)
        return 2
    with open(sys.argv[1], encoding="utf-8") as fh:
        doc = json.load(fh)
    vectors = doc.get("vectors") or []
    if not vectors:
        print("corpus has no canon vectors", file=sys.stderr)
        return 1
    failures = 0
    for v in vectors:
        want = v["canonical"]
        got = canonicalize(v["cert"]).decode("utf-8")
        if got == want:
            print(f"PASS {v['name']}")
        else:
            print(f"FAIL {v['name']}\n  got:  {got}\n  want: {want}")
            failures += 1
    if failures:
        print(f"{failures} vector(s) mismatched", file=sys.stderr)
        return 1
    print("canonicalization reproduces every shared vector")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
