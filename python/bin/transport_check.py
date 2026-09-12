#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["bonemesh"]
#
# [tool.uv.sources]
# bonemesh = { path = "..", editable = true }
# ///
"""Reads the shared transport-frame vector
(spec/corpus/transcripts/transport-frame.json) and confirms this transport both
reproduces the sealed ciphertext byte-for-byte and can open it again.

The vector states both halves ("reproduces ct_hex and can open it"), so both are
asserted: sealing alone would pass even if opening were broken, and opening alone
would pass a transport that agreed with itself but not with the other
implementations. Invoked by interop/check-transport-python.sh.
"""

import json
import sys

from bonemesh.transport import open_ciphertext, seal_ciphertext


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: transport_check <transport-frame.json>", file=sys.stderr)
        return 2
    with open(sys.argv[1], encoding="utf-8") as fh:
        doc = json.load(fh)
    i, o = doc["inputs"], doc["outputs"]
    failures = 0

    def check(name: str, got: str, want: str) -> None:
        nonlocal failures
        if got == want:
            print(f"PASS {name}")
        else:
            print(f"FAIL {name}\n  got:  {got}\n  want: {want}")
            failures += 1

    key = bytes.fromhex(i["key_hex"])
    seq = int(i["seq"])
    inner = bytes.fromhex(i["inner_plaintext_hex"])

    check("ct_hex", seal_ciphertext(key, seq, inner).hex(), o["ct_hex"])

    opened = open_ciphertext(key, seq, bytes.fromhex(o["ct_hex"]))
    if opened is None:
        print("FAIL inner_plaintext_hex\n  got:  <authentication failed>")
        failures += 1
    else:
        check("inner_plaintext_hex", opened.hex(), i["inner_plaintext_hex"])

    if failures:
        print(f"{failures} output(s) mismatched", file=sys.stderr)
        return 1
    print("transport frame seals and opens to the shared vector")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
