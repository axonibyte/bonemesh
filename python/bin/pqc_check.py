#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["bonemesh"]
#
# [tool.uv.sources]
# bonemesh = { path = "..", editable = true }
# ///
"""Verifies this port's post-quantum interop against the shared vector
(spec/corpus/transcripts/pqc-interop.json), produced by the Java reference
(BouncyCastle).

It verifies the ML-DSA-65 signature over the vector's message using the vector's
public key, exercising the node's real mldsa65_verify. Success proves Python and
Java agree on ML-DSA-65 at the byte level.

It does NOT decapsulate the vector's ML-KEM ciphertext: the vector ships a
2400-byte FIPS *expanded* decapsulation key, while this port (like Go, JS and PHP)
is keyed by the 64-byte seed. That is a private-key *representation* difference,
not an interop gap -- a decapsulation key never crosses a node, only the
encapsulation key, ciphertext and public artifacts do, all standard FIPS
encodings. Live ML-KEM-768 interop is proven directly by the interop matrix. This
tool names that boundary rather than loading a key format the node never receives.

Invoked by interop/check-pqc-python.sh.
"""

import json
import sys

from bonemesh.crypto import mldsa65_verify


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: pqc_check <pqc-interop.json>", file=sys.stderr)
        return 2
    with open(sys.argv[1], encoding="utf-8") as fh:
        v = json.load(fh)["mldsa65"]
    ok = mldsa65_verify(bytes.fromhex(v["public_hex"]),
                        bytes.fromhex(v["message_hex"]),
                        bytes.fromhex(v["signature_hex"]))
    if not ok:
        print("FAIL: Python did not verify the Java ML-DSA-65 signature", file=sys.stderr)
        return 1
    print("PASS: Python verifies the Java ML-DSA-65 signature over the shared vector")
    print("NOTE: ML-KEM-768 interop with Java is proven live by the interop matrix")
    print("      (this port's ML-KEM is seed-keyed; the vector's expanded dk is a")
    print("      key-representation detail that never crosses a node).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
