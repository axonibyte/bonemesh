#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["bonemesh"]
#
# [tool.uv.sources]
# bonemesh = { path = "..", editable = true }
# ///
"""Reads the shared key-schedule vector (spec/corpus/transcripts/keyschedule.json)
and confirms this symmetric state reproduces every output.

Agreement with the other implementations over this file means a handshake driven
by any of them derives the same transport keys. Invoked by
interop/check-keyschedule-python.sh.
"""

import json
import sys

from bonemesh.keyschedule import KeySchedule


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: keyschedule_check <keyschedule.json>", file=sys.stderr)
        return 2
    with open(sys.argv[1], encoding="utf-8") as fh:
        doc = json.load(fh)
    i, o = doc["inputs"], doc["outputs"]
    hx = bytes.fromhex
    failures = 0

    def check(name: str, got: bytes, want: str) -> None:
        nonlocal failures
        if got.hex() == want:
            print(f"PASS {name}")
        else:
            print(f"FAIL {name}\n  got:  {got.hex()}\n  want: {want}")
            failures += 1

    s = KeySchedule()
    check("h_init", s.h, o["h_init"])
    s.mix_hash(hx(i["mesh_hex"]))
    check("h_after_mesh", s.h, o["h_after_mesh"])
    s.mix_key(hx(i["ss_dh_hex"]))
    check("ck_after_dh", s.ck, o["ck_after_dh"])
    s.mix_key(hx(i["ss_kem_hex"]))
    check("ck_after_kem", s.ck, o["ck_after_kem"])
    check("ct1", s.encrypt_and_hash(hx(i["plaintext1_hex"])), o["ct1_hex"])
    check("h_after_ct1", s.h, o["h_after_ct1"])
    check("ct2", s.encrypt_and_hash(hx(i["plaintext2_hex"])), o["ct2_hex"])
    check("h_after_ct2", s.h, o["h_after_ct2"])
    i2r, r2i = s.split()
    check("transport_key_i2r", i2r, o["transport_key_i2r"])
    check("transport_key_r2i", r2i, o["transport_key_r2i"])

    if failures:
        print(f"{failures} output(s) mismatched", file=sys.stderr)
        return 1
    print("key schedule reproduces every shared output")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
