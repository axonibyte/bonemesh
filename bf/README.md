# bf — BoneMesh's symmetric core, in brainfuck

A BoneMesh port written in **brainfuck**. Not a joke, and not a whole node: it
implements the parts of BMX that are symmetric cryptography, checks them
against the same frozen corpus every other port is checked against, and stops
where brainfuck honestly stops.

```
spec/corpus/transcripts/transport-frame.json   reproduced,  6 s
spec/corpus/transcripts/keyschedule.json       reproduced, 91 s
same frame, sealed and sent through a TCP socket    reproduced
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

## The goal is full interoperability, and this is the road to it

**A port that cannot talk to the other ports is not a port.** What exists today
is the symmetric core checked against the frozen corpus — the same footing
Elixir and Rust are on for the key schedule — and that is a waypoint rather
than the destination. The destination is a bf node that completes a real BMX
handshake with a Java or Go node over a socket.

Two kinds of interoperability exist in this repository and they are not the
same claim:

| | what it proves | bf today |
|---|---|---|
| **corpus agreement** | everyone computes the same frozen bytes | **done**, both vectors |
| **a socket** | brainfuck puts bytes on a wire under brainstem | **done**, `check-transport-socket-bf.sh` |
| **live pairing** (`interop/run-matrix.sh`) | two nodes complete a real hybrid handshake | not yet |

### The road, in the order it is worth building

**1. A socket. DONE.** `bf/transport-socket.poke` binds an ephemeral port,
listens, connects to it, accepts, seals the transport frame and sends the
ciphertext through the socket, then reads it back off the accepted end -- and
it lands on the same forty six bytes the frozen vector holds. Nothing new was
needed from the crypto: brainstem already
ships `socket` `connect` `bind` `listen` `accept` as ops `0x05`–`0x09`, built
and gated on both its guests, and its own `bf/net/loopback6` fixture proves a
brainfuck program can bind an ephemeral port, listen, connect to it, accept and
exchange bytes. **That step turned "bf computes the same bytes" into
"bf sent bytes to something".**

**2. A cheaper `mulmod136`. DONE**, and it moved step 4's headline more than
its own. A Montgomery ladder performs about 2550 field multiplications, so
every instruction saved in the multiply is saved 2550 times -- which is why
this came before step 4 rather than after. Two changes in bfsodium, both tape
layout rather than algorithm and both measured before they were built:
`poly1305/fold136` now places five times the part above bit 130 as ONE two
byte addend instead of entering the adder five times, and `poly1305/mulmod136`
was relaid so that every pasted kernel runs AT the variable it operates on and
nothing is carried to a work frame. `b` is walked a byte at a time rather than
shifted right one bit per turn.

| | before | after | |
| ---|--- | --- | 0 |
| `mulmod136`, large vector | 987,082,567 | 89,473,525 | **11.0x** |
| AEAD, RFC 8439 2.8.2 | 11,584,909,050 | 1,937,080,043 | **5.98x** |

More than half of the original went on carrying seventeen byte operands to and
from a work frame, which nobody had counted, and only 7% on every kernel put
together.

**And the remaining item named here has since been taken, and was not what it
said it was.** This paragraph used to ask for a second fold specialised to the
value a doubling leaves behind. The measurement said otherwise: `fold136` was
entering `add136`, which is seventeen entries of `add8`, to add a number that
is at most two bytes — and `add8` costs the same whatever its addend is,
because nearly all of it is finding bit 7 of the *accumulator*. Fifteen of
those seventeen entries were adding nothing. `fold136` now adds its two bytes
with two entries of `add8` and lets the carry ripple, which took `mulmod136`
from 145,361,714 to 89,473,525 with no new file at all. The AEAD's other
1.57x in the table above is ChaCha's rotation, rebuilt so that it never
shifts left. See bfsodium's `HANDOFF.md` under *Cost* for both profiles.

**3. Keccak-f[1600]. DONE**, and the whole of FIPS 202 with it: the
permutation, the sponge at three rates, SHA3-224/256/384/512 and SHAKE128 and
SHAKE256. **SHAKE128 is the one ML-KEM actually calls** — its matrix sampling
is a SHAKE128 squeeze of a few hundred bytes per entry — so step 4's
prerequisite is in hand. The permutation is 2,483,822,414 instructions, about
four seconds, after the round's tape was re-laid for a 1.59x that cost no
change to the arithmetic at all.

**4. ML-KEM-768 and X25519** — the hybrid handshake needs both, so neither
alone finishes the job.

### The cost, and a result that inverts the usual intuition

**ML-KEM is the cheap half and X25519 is the expensive one.** That is backwards
from most platforms and it follows directly from this one having no arithmetic:

- ML-KEM's arithmetic is all mod **q = 3329**, a 13-bit modulus, so a modular
  multiply is a **two-limb** multiply. The work is thousands of cheap
  butterflies. Plausibly minutes per operation.
- X25519's field is **2²⁵⁵−19**, thirty-two limbs. `mulmod136` is a measured
  **89,473,525 instructions** at seventeen limbs, and partial products go as
  the square of the limb count — so about **317 million** per multiply, times
  ~2550 for a ladder, is on the order of **twenty-two minutes per scalar
  multiplication**. That number was **four hours** before step 2, on a
  `mulmod136` of 987 million, and **35 minutes** at the 145 million step 2
  first reached; the estimate scales with the multiply and so does the next
  improvement to it.

X25519 is in scope *because of the shape of its prime*: 2²⁵⁵−19 is
pseudo-Mersenne, reduced by multiplying the high half by a small constant and
adding — exactly what `poly1305/mulmod136` already does for 2¹³⁰−5. bfsodium's
`CONVENTIONS.md` §9.1 said elliptic curve was out of scope on the grounds that
that trick does not transfer; it does not transfer to RSA or to the NIST
P-curves, and it transfers exactly to Curve25519. That section has been
corrected.

**RSA and the NIST P-curves remain out of scope**, and BMX needs neither.

## What it is not, today

- **No handshake yet.** X25519 and ML-KEM-768 are steps 3 and 4 above. The
  key-schedule vector supplies `ss_dh_hex` and `ss_kem_hex` as *inputs*, which
  is exactly why the symmetric half could be checked first and on its own.
- **No node and no certificates.** The socket path works, but nothing here
  speaks to a peer in another language yet -- that is the handshake.
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
sh interop/check-transport-bf.sh          # the sealed frame
sh interop/check-transport-socket-bf.sh   # the same frame, over a socket
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
