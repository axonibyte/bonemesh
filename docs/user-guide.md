# BoneMesh User Guide

BoneMesh is a point-to-point mesh networking protocol with six interoperating
implementations — Java, Go, Rust, PHP, Elixir, and JavaScript (Node.js). A node
written in any of them speaks the same wire protocol, so a mesh can be any mix
of languages. Traffic is authenticated and encrypted end to end on each hop with
post-quantum cryptography, and nodes route for each other so a message reaches a
destination it is not directly connected to.

This guide is task-oriented: what the pieces are, how to stand up a mesh, how to
run and embed a node, and what you are responsible for operationally. For the
normative wire format see [`spec/protocol.md`](../spec/protocol.md); for the
cryptographic design see [`spec/security.md`](../spec/security.md); for how the
internals fit together see [`architecture.md`](architecture.md).

---

## 1. Concepts

- **Mesh** — a named group of nodes that trust the same root. The mesh id is a
  short string (e.g. `acme-prod`); a node only talks to peers in the same mesh.
- **Node** — one running participant, identified by a **label** (e.g. `edge-1`).
  Labels are how you address messages; treat them as lowercase and unique within
  a mesh.
- **Mesh root** — the trust anchor: an ML-DSA-87 key pair. Its **public** key is
  pinned into every node; its **private** key signs membership certificates and
  must be guarded (it is the whole mesh's trust).
- **Membership certificate** — a small signed JSON document binding a label to a
  node's identity public key, with a validity window. A node presents it during
  the handshake; peers accept it only if the root signature verifies, the mesh
  matches, and it is currently valid.
- **Identity key** — each node's own ML-DSA-65 key pair. The private key never
  leaves the node; only the public key is certified and only public
  keys/ciphertexts/signatures ever cross the wire.

A node needs three things to join a mesh: the **root public key**, its
**membership certificate**, and its **identity private key**.

---

## 2. Provisioning a mesh

Provisioning is done once with the bundled certificate authority, `bonemesh-ca`
(a small Go command under `go/cmd/bonemesh-ca`). Its output — keys and
certificates as base64 and JSON files — is implementation-neutral: a
certificate issued here is accepted by a node in any language.

Build the tool (needs a Go toolchain), then create a root:

```sh
cd go && go build -o bonemesh-ca ./cmd/bonemesh-ca
CA="./bonemesh-ca"

$CA init-root --out ./ca                # writes ca/root.pub and ca/root.priv
```

Guard `ca/root.priv` — anyone holding it can mint members. Distribute only
`ca/root.pub`.

Each node generates its **own** identity key pair (in its own private-key
format — the format never matters to anyone else), and the CA issues a
certificate over the public half:

```sh
# a node makes its own keypair (any implementation's keygen does this);
# here via the Go node runner, writing raw public + private key files:
interop/drivers/go.sh keygen --id-pub edge-1.pub --id-priv edge-1.priv

# the CA signs a membership certificate over the public key
$CA issue --root-priv ca/root.priv --root-pub ca/root.pub \
    --mesh acme-prod --label edge-1 --key edge-1.pub --days 30 --out edge-1.cert.json
```

`edge-1.cert.json` + `edge-1.priv` + `ca/root.pub` are everything `edge-1` needs.
`verify` checks a certificate the way a node does:

```sh
$CA verify --root-pub ca/root.pub --mesh acme-prod --cert edge-1.cert.json
```

The private key `edge-1.priv` was produced by the Go runner in **Go's** format;
if `edge-1` will run in Rust, generate it with `interop/drivers/rust.sh keygen`
instead. The certificate (which carries the *public* key) is identical either
way — pick the keygen that matches the language the node will run in.

---

## 3. Running a node

Every implementation ships a small node runner used by the interop harness and
handy for trying a mesh out. They all speak the same command contract
(`interop/README.md`): `keygen`, `listen`, `connect`, and `mesh`. The runners
are `interop/drivers/{java,go,rust,elixir,js,php}.sh`.

Common flags: `--mesh`, `--root-pub`, `--cert`, `--id-pub`, `--id-priv`, and
`--seconds` (how long to stay up).

**A listener** accepts connections and writes each delivered payload (one JSON
object per line) to `--out`:

```sh
interop/drivers/go.sh listen --port 7001 --mesh acme-prod \
  --root-pub ca/root.pub --cert edge-1.cert.json \
  --id-pub edge-1.pub --id-priv edge-1.priv --out edge-1.received --seconds 60
```

**A connector** dials a peer, completes the handshake, and sends one message
(`--message` is a JSON file) toward `--to`:

```sh
interop/drivers/rust.sh connect --mesh acme-prod \
  --root-pub ca/root.pub --cert edge-2.cert.json \
  --id-pub edge-2.pub --id-priv edge-2.priv \
  --host 127.0.0.1 --port 7001 --to edge-1 --message hello.json --seconds 10
```

Here a Rust node hands a message to a Go node — the languages are irrelevant to
each other. `edge-1.received` gains a line with the payload.

**A multi-link node** (`mesh`) dials several `--peers` (`host:port,host:port`),
optionally streams to a routed destination (`--send-to` + `--message`), and can
dump its routing table to `--routes`. This is how you build topologies larger
than a single link (see §6).

---

## 4. Messages: what you send

A BoneMesh message is just an application **payload** — any JSON value —
addressed to a destination label. Those two things are all you supply; the node
builds the wire envelope around them for you, so you never construct a message by
hand. Specifically, the node generates:

- a **message id** (`mid`) — a random 128-bit value it uses for de-duplication
  and to correlate acknowledgements;
- **`from`** — set to your node's own certificate-bound label. It is
  authenticated, so a node cannot forge another node's origin;
- a **hop limit** (`ttl`, default 16), decremented at each relay;
- **chunking** — a payload larger than one transport frame (64 KiB by default)
  is split at the origin and reassembled at the destination, so the frame size
  never caps how large a payload may be.

What arrives at the destination's listener is exactly the payload value you sent,
not the envelope. For the full wire shape of a `data` message, see
[`spec/protocol.md`](../spec/protocol.md) §4.

Constraints and guarantees worth knowing:

- The payload must be JSON-serializable. By convention it is a JSON object, and
  the reference drivers' `--message` flag expects the file to contain an object.
- Delivery is **unordered** and best-effort along a live path. `mid` gives
  de-duplication (a redelivered message is dropped once), not ordering — if you
  need ordering or an end-to-end receipt, carry a sequence number or request id
  inside your own payload and have the peer reply.
- `send` reports whether the destination is currently **routable**, not whether
  it was delivered end to end: `true` means a path exists and the message was
  handed to the next hop.

**In code**, pass the payload straight to `send`:

```go
n.Send("edge-2", map[string]any{"kind": "reading", "temp_c": 21.4, "seq": 7})
```
```js
n.send("edge-2", { kind: "reading", temp_c: 21.4, seq: 7 });
```

**Via a driver**, the payload is a JSON file given to `--message`, sent toward
`--to` (a single `connect` send) or `--send-to` (streamed by a `mesh` node):

```sh
printf '%s\n' '{ "kind": "reading", "temp_c": 21.4, "seq": 7 }' > reading.json

interop/drivers/go.sh connect --mesh acme-prod \
  --root-pub ca/root.pub --cert edge-2.cert.json \
  --id-pub edge-2.pub --id-priv edge-2.priv \
  --host 127.0.0.1 --port 7001 --to edge-1 --message reading.json --seconds 10
```

---

## 5. Embedding a node (library API)

Each implementation is also a library. A node takes the same three inputs (root
public key, certificate, identity private key) plus a mesh id and label, and
exposes: start/listen, connect to a peer, send toward a label, register a
delivery callback, and stop. Sketch per language:

**Go**
```go
n, _ := node.Start(node.Config{
    Label: "edge-1", Mesh: "acme-prod",
    RootPublic: rootPub, Cert: cert, IDPrivate: idPriv,
}, 7001)
ch := n.AddListener()          // <-chan map[string]any of delivered payloads
n.Connect("10.0.0.2", 7002)
n.Send("edge-2", map[string]any{"hello": "world"})
```

**Rust**
```rust
let n = Node::start(Config { label, mesh, root_public, cert, id_private }, 7001)?;
let rx = n.add_listener();     // mpsc::Receiver<Value>
n.connect("10.0.0.2", 7002)?;
n.send("edge-2", json!({"hello": "world"}));
```

**JavaScript (Node.js)**
```js
const n = await Node.start({ label, mesh, rootPublic, cert, idPrivate }, 7001);
n.onMessage((payload) => console.log(payload));
await n.connect("10.0.0.2", 7002);
n.send("edge-2", { hello: "world" });
```

**Java**
```java
Node n = Node.start("edge-1", "acme-prod", rootPub, cert, identity, 7001);
n.addDataListener(payload -> System.out.println(payload));
n.connect("10.0.0.2", 7002);
n.send("edge-2", new JSONObject().put("hello", "world"));
```

**Elixir** (a `GenServer`)
```elixir
{:ok, n} = Bonemesh.Node.start_link(
  label: "edge-1", mesh: "acme-prod", root_public: root_pub,
  cert: cert, id_public: id_pub, id_private: id_priv, port: 7001)
Bonemesh.Node.add_listener(n, self())   # receives {:bonemesh_data, payload}
Bonemesh.Node.connect(n, "10.0.0.2", 7002)
Bonemesh.Node.send(n, "edge-2", %{"hello" => "world"})
```

**PHP** (single-threaded; drive it with `serve`)
```php
$n = Node::start($config, 7001);
$n->onMessage(fn($payload) => print(json_encode($payload) . "\n"));
$n->connect("10.0.0.2", 7002);
$n->send("edge-2", ["hello" => "world"]);
$n->serve(60);   // runs the accept/heartbeat/relay loop for 60s
```

`send` returns whether the destination is currently routable. A node delivers to
its listeners only payloads addressed to its own label; anything else it relays.

---

## 6. Building a routed mesh

Nodes discover each other's reachability automatically. Every second a node
sends each neighbor a liveness probe and a route advertisement; from those it
builds a distance-vector table of which neighbor to forward through to reach a
given label. A message carries a hop limit (TTL, default 16) and is
re-encrypted on each hop.

So you do **not** need a full mesh of direct links. In a line `A — B — C`, once
routes converge `A` can `send` to `C` and `B` relays it. Build such a topology
by having the middle node accept and the others dial it, or use the `mesh`
runner to give a node several links at once:

```sh
# B is a relay: it just listens and forwards.
interop/drivers/java.sh listen --port 7002 --mesh acme-prod \
  --root-pub ca/root.pub --cert B.cert.json --id-pub B.pub --id-priv B.priv \
  --out /dev/null --seconds 120 &

# A dials B and streams to C; C dials B and receives.
interop/drivers/go.sh   mesh --peers 127.0.0.1:7002 --send-to C --message hi.json \
  --mesh acme-prod --root-pub ca/root.pub --cert A.cert.json --id-pub A.pub --id-priv A.priv --seconds 60 &
interop/drivers/js.sh   mesh --peers 127.0.0.1:7002 --out C.received \
  --mesh acme-prod --root-pub ca/root.pub --cert C.cert.json --id-pub C.pub --id-priv C.priv --seconds 60 &
```

If a relay dies, its neighbors withdraw the routes through it and the mesh
re-converges onto any surviving path — with no configuration change. Only
delivery over a still-connected path is guaranteed; a fully partitioned
destination is simply unreachable until the partition heals.

---

## 7. Security model, from the operator's side

- **The mesh root private key is the whole mesh's trust.** Keep it offline; use
  it only to issue certificates. Its compromise means an attacker can mint valid
  members.
- **A node's identity private key stays on that node.** It is never transmitted
  and never needs to be — only public keys, ciphertexts, and signatures cross
  the wire, all standard FIPS/RFC encodings.
- **Every link is mutually authenticated and encrypted.** The handshake (BMX)
  proves both peers hold a root-signed certificate for their claimed label and
  establishes a forward-secret session using a hybrid of X25519 and ML-KEM-768,
  so a recording captured today cannot be decrypted by a future quantum
  adversary. Application traffic is ChaCha20-Poly1305.
- **Trust is hop-by-hop.** A relay decrypts a message to route it, so a message
  is protected on each link but not opaque to the relays it transits. End-to-end
  payload encryption is a deliberate non-goal of v3; if you need it, encrypt the
  payload yourself before `send`.
- **Certificates expire.** Issue with a validity window (`--days`) suited to
  your rotation policy; a node rejects an expired or not-yet-valid peer cert.

For the full trust and threat model see [`spec/security.md`](../spec/security.md)
§7.

---

## 8. Debugging encrypted traffic

Because the protocol is JSON under channel encryption, it is designed to be
inspectable during development without weakening production. As of 3.1.0 every
implementation ships a session-key logging hook (in the spirit of
`SSLKEYLOGFILE`), and the `bonemesh-inspect` tool reads a captured stream back
into cleartext; see [`spec/security.md`](../spec/security.md) §8.

Set `BONEMESH_KEYLOG` to a writable path and the node appends one line per
directional traffic key as each session is established or rekeyed — the format
is pinned in `spec/security.md` §8:

```
BMX3_I2R_TRAFFIC_<epoch> <hex transcript-hash> <hex 32-byte key>
BMX3_R2I_TRAFFIC_<epoch> <hex transcript-hash> <hex 32-byte key>
```

Epoch 0 is the initial handshake; the counter increments on each rekey. The
node prints a loud warning for every session while a keylog is active, so it is
obvious when this is on. It is off unless the variable is set.

Given a keylog and a captured frame stream (NDJSON, one
`{"dir":"i2r"|"r2i","frame":{seq,ct}}` per line), `bonemesh-inspect` decrypts
the transport back to the inner messages:

```
bonemesh-inspect --keylog keys.log --capture session.ndjson
```

It matches each direction's newest epoch first and lets the Poly1305 tag
arbitrate, so a capture that spans a rekey is read without the tool having to
parse the rekey exchange itself. This exposes only what the keylog holder could
already decrypt — it is a development aid, not a downgrade of the channel.

You can still inspect payloads at the application boundary instead — log what
you `send` and what your listener receives — but there is no longer any reason
to disable encryption to see traffic.

For protocol-level questions, the shared test corpus under
[`spec/corpus/`](../spec/corpus/) contains worked examples of canonical
certificates, frames, message-schema verdicts, and handshake transcripts that
show exactly what valid traffic looks like.

---

## 9. Interoperability

Any node interoperates with any other regardless of language: the six
implementations are checked pairwise, in both directions, by the interop matrix
(`interop/run-matrix.sh`), and jointly under fault injection, a degraded
network, seeded fuzzing, routed-mesh convergence, and simulated churn (interop
tiers 5–9). If you write against one implementation, the others behave
identically on the wire.

---

## 10. Troubleshooting

- **`send` returns false / message not delivered.** The destination is not
  routable yet. Give discovery a couple of seconds after connecting, confirm the
  destination shares the mesh id, and confirm a path exists (a direct link or a
  live relay chain).
- **Handshake rejected.** Usually a certificate problem: wrong mesh id, expired
  or not-yet-valid window, or a certificate signed by a different root than the
  peer pins. Re-run `bonemesh-ca verify`.
- **A node received nothing across a partition.** That is correct — BoneMesh
  never delivers across a break in the topology. Delivery resumes after heal.
- **Which keygen do I use?** The one matching the language the node will run in;
  the private-key file is that implementation's own format. The certificate is
  language-neutral.
