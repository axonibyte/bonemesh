# bf — BoneMesh's symmetric core, in brainfuck

A BoneMesh port written in **brainfuck**. Not a joke, and not a whole node: it
implements the parts of BMX that are symmetric cryptography, checks them
against the same frozen corpus every other port is checked against, and stops
where brainfuck honestly stops.

```
spec/corpus/transcripts/transport-frame.json   reproduced,  6 s
spec/corpus/transcripts/keyschedule.json       reproduced, 91 s
```

## What this is, exactly

Three projects stack up to make it possible, and the dependency direction is
strict — infrastructure never knows its consumers:

| | is | provides |
|---|---|---|
| [bfsodium](https://github.com/calebpower/bfsodium) | hand-written brainfuck crypto | SHA-256, HMAC, HKDF, ChaCha20, Poly1305, ChaCha20-Poly1305 |
| [brainstem](https://github.com/calebpower/brainstem) | a syscall broker for standard brainfuck | pipes, spawn, read, write over a byte protocol on stdin/stdout |
| this directory | the BoneMesh part | the BMX key schedule and transport frame, as brainfuck programs |

**Every file in this directory that ends in `.bf` contains nothing but the
eight brainfuck instructions and whitespace, plus `;` comments whose prose is
proved inert.** They run under any conforming interpreter. They reach pipes and
processes by *speaking a byte protocol over their own stdin and stdout* to
brainstem — no language extension, no ninth instruction.

## What it is not

- **No handshake.** X25519 and ML-KEM-768 are not implemented and are not
  planned; `bfsodium` has no public-key primitive and adding one is a different
  project with a different cost model. The key-schedule vector supplies
  `ss_dh_hex` and `ss_kem_hex` as *inputs*, which is exactly why the symmetric
  half can be checked on its own.
- **No node, no transport, no certificates.** Nothing here opens a socket or
  speaks to a peer.
- **No JSON.** The check scripts extract hex fields from the corpus with `sed`
  and convert them to bytes, then feed raw bytes to a brainfuck program. That
  is the same division every other port makes — Go reads the vector with Go's
  JSON parser, not with Go's crypto. **Every cryptographic operation, and all
  the sequencing between them, happens in brainfuck.** Parsing JSON in
  brainfuck would add nothing to the conformance claim.

## Why the key schedule is the interesting one

`transport-frame.json` is one AEAD call. `keyschedule.json` is nine calls where
each output is the next call's input:

```
init(protocol_name); mixHash(mesh); mixKey(ss_dh); mixKey(ss_kem);
ct1 = encryptAndHash(plaintext1); ct2 = encryptAndHash(plaintext2); split()
```

A brainfuck program holds `h`, `ck` and the message key on its own tape,
spawns an interpreter on the right bfsodium routine for each step, feeds it the
bytes, reads the answer back, and carries it into the next step. **No shell in
the middle.** That is the claim neither bfsodium nor brainstem could make on
its own: bfsodium proves each routine correct, brainstem proves the broker
works, and neither proves the join.

## Running it

```sh
sh bf/setup.sh                         # clone and build the pinned toolchain
sh interop/check-transport-bf.sh
sh interop/check-keyschedule-bf.sh
```

`setup.sh` pins **bfsodium by commit**, which in turn pins brainstem by
commit. Nothing is vendored: two copies of a crypto routine are two things
that can disagree, and the pin is what makes a run reproducible.

## The cost, because it is the honest headline

Brainfuck has no arithmetic. SHA-256 of one 64-byte block is about **1.15
billion interpreter instructions, roughly two seconds**.

**All ten of the key schedule's frozen intermediates** are reproduced, not just
the two transport keys: `h_init`, `h_after_mesh`, `ck_after_dh`, `ck_after_kem`,
both ciphertexts, both hashes of them, and both directional keys. **Ninety one
seconds** for nine sequenced routine calls — four hashes, three HKDF calls and
two AEAD seals.

That number is worth stating plainly because the estimate was badly wrong. HKDF
is bfsodium's largest routine at 294912 lines and three calls to it were
expected to dominate at tens of minutes; the whole schedule runs in a minute
and a half. Line count is not instruction count — most of `hkdf.bf` is a pasted
`hashcore` reached once per HMAC block, and the schedule hashes very little
data. **The only honest cost is a measured one**, which is why the figure at the
top of this file is a stopwatch reading rather than an extrapolation.

This is not a performance story and never was. It is a *legibility* story: the
claim is that a cryptographic protocol's symmetric core can be implemented in
the smallest Turing-complete language there is, by hand, and still be checked
against the same bytes as five other implementations.
