#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["bonemesh"]
#
# [tool.uv.sources]
# bonemesh = { path = "..", editable = true }
# ///
"""Reads the shared hybrid key-agreement vector
(spec/corpus/transcripts/handshake-agreement.json) and confirms this
implementation reproduces the transcript checkpoints and transport keys.

Sequence (security.md §5): mix_hash(mesh, ei_pub, ki_ek, n); mix_hash(er_pub);
mix_key(ss_dh); mix_hash(kem_ct); mix_key(ss_kem); split().

The X25519 secret is DERIVED from ei_priv and er_pub rather than read out of the
vector, then compared against the vector's ss_dh_hex. That is a second oracle the
schedule alone cannot give: feeding the vector's own ss_dh straight into mix_key
would still pass on an implementation whose X25519 agreement was broken, because
nothing would ever have computed it. Go, Java and Elixir derive it the same way.

Invoked by interop/check-agreement-python.sh.
"""

import json
import sys

from cryptography.hazmat.primitives.asymmetric import x25519

from bonemesh.crypto import x25519_agree
from bonemesh.keyschedule import KeySchedule


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: agreement_check <handshake-agreement.json>", file=sys.stderr)
        return 2
    with open(sys.argv[1], encoding="utf-8") as fh:
        doc = json.load(fh)
    i, o = doc["inputs"], doc["outputs"]
    hx = bytes.fromhex
    failures = 0

    def check(name: str, got: str, want: str) -> None:
        nonlocal failures
        if got == want:
            print(f"PASS {name}")
        else:
            print(f"FAIL {name}\n  got:  {got}\n  want: {want}")
            failures += 1

    priv = x25519.X25519PrivateKey.from_private_bytes(hx(i["ei_priv_hex"]))
    ss_dh = x25519_agree(priv, hx(i["er_pub_hex"]))
    check("ss_dh (derived)", ss_dh.hex(), i["ss_dh_hex"])

    s = KeySchedule()
    s.mix_hash(hx(i["mesh_hex"]))
    s.mix_hash(hx(i["ei_pub_hex"]))
    s.mix_hash(hx(i["ki_ek_hex"]))
    s.mix_hash(hx(i["n_hex"]))
    check("h_after_msg1", s.h.hex(), o["h_after_msg1"])

    s.mix_hash(hx(i["er_pub_hex"]))
    s.mix_key(ss_dh)
    check("ck_after_dh", s.ck.hex(), o["ck_after_dh"])

    s.mix_hash(hx(i["kem_ct_hex"]))
    s.mix_key(hx(i["ss_kem_hex"]))
    check("ck_after_kem", s.ck.hex(), o["ck_after_kem"])

    # The msg-2 checkpoint is taken once both message-2 hash inputs (responder
    # ephemeral and KEM ciphertext) are absorbed; mix_key does not alter h.
    check("h_after_msg2_ephemerals", s.h.hex(), o["h_after_msg2_ephemerals"])

    i2r, r2i = s.split()
    check("transport_key_i2r", i2r.hex(), o["transport_key_i2r"])
    check("transport_key_r2i", r2i.hex(), o["transport_key_r2i"])

    if failures:
        print(f"{failures} checkpoint(s) mismatched", file=sys.stderr)
        return 1
    print("hybrid key agreement reproduces every shared checkpoint")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
