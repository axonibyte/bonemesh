// End-to-end BMX handshake tests (security.md §4). Runs the full three-message
// exchange between two in-process parties holding real root-signed certificates,
// asserts both sides derive matching directional transport keys and each other's
// certificate, exercises a transport round-trip over the result, and self-tests
// the authentication oracle by tampering with inputs and pinning a foreign root.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { Handshake } from '../src/handshake.js';
import { Transport } from '../src/transport.js';
import { classify, encode, HANDSHAKE_CAP, TRANSPORT_CAP } from '../src/frame.js';
import { build } from '../src/cert.js';
import { canonicalize } from '../src/canon.js';
import { mldsa65Generate } from '../src/crypto.js';

const MESH = 'acme-prod';
const NOW = 1500;

function newRoot() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ml-dsa-87');
  const pubRaw = Buffer.from(publicKey.export({ format: 'jwk' }).pub, 'base64url');
  return { pubRaw, privateKey };
}

function issue(root, label) {
  const { pub, priv } = mldsa65Generate();
  const cert = build(MESH, label, pub, 1000, 2000);
  const sig = crypto.sign(null, Buffer.from(canonicalize(cert), 'utf8'), root.privateKey);
  cert.sig = sig.toString('base64');
  return { cert, idPrivate: priv };
}

// Decode a written frame Buffer into its object, as a peer would off the wire.
const dec = (buf) => classify(buf, HANDSHAKE_CAP).obj;

test('full handshake derives matching keys and delivers over transport', () => {
  const root = newRoot();
  const i = issue(root, 'initiator');
  const r = issue(root, 'responder');
  const init = Handshake.initiator(MESH, root.pubRaw, NOW, i.cert, i.idPrivate);
  const resp = Handshake.responder(MESH, root.pubRaw, NOW, r.cert, r.idPrivate);

  const m2 = dec(resp.readMessage1WriteMessage2(dec(init.writeMessage1())));
  const m3 = dec(init.readMessage2WriteMessage3(m2));
  resp.readMessage3(m3);

  const is = init.session, rs = resp.session;
  assert.deepEqual(is.sendKey, rs.receiveKey);
  assert.deepEqual(is.receiveKey, rs.sendKey);
  assert.equal(is.peerCert.label, 'responder');
  assert.equal(rs.peerCert.label, 'initiator');

  // Each carrier crosses the frame wire so seq behaves exactly as between nodes.
  const it = new Transport(is), rt = new Transport(rs);
  const wire = (carrier) => classify(encode(carrier), TRANSPORT_CAP).obj;
  const got = rt.open(wire(it.seal({ type: 'data', payload: { hi: 'there' } })));
  assert.equal(got.payload.hi, 'there');
  assert.doesNotThrow(() => it.open(wire(rt.seal({ type: 'ack' }))));
});

test('responder pinning a foreign root rejects the initiator at msg3', () => {
  const root = newRoot();
  const foreign = newRoot();
  const i = issue(root, 'initiator');
  const r = issue(root, 'responder');
  const init = Handshake.initiator(MESH, root.pubRaw, NOW, i.cert, i.idPrivate);
  const resp = Handshake.responder(MESH, foreign.pubRaw, NOW, r.cert, r.idPrivate);

  const m2 = dec(resp.readMessage1WriteMessage2(dec(init.writeMessage1())));
  const m3 = dec(init.readMessage2WriteMessage3(m2));
  assert.throws(() => resp.readMessage3(m3));
});

test('foreign mesh is rejected at msg1', () => {
  const root = newRoot();
  const i = issue(root, 'initiator');
  const r = issue(root, 'responder');
  const resp = Handshake.responder(MESH, root.pubRaw, NOW, r.cert, r.idPrivate);
  const bad = dec(Handshake.initiator('other-mesh', root.pubRaw, NOW, i.cert, i.idPrivate).writeMessage1());
  assert.throws(() => resp.readMessage1WriteMessage2(bad));
});

test('tampered responder auth is rejected by the initiator', () => {
  const root = newRoot();
  const i = issue(root, 'initiator');
  const r = issue(root, 'responder');
  const init = Handshake.initiator(MESH, root.pubRaw, NOW, i.cert, i.idPrivate);
  const resp = Handshake.responder(MESH, root.pubRaw, NOW, r.cert, r.idPrivate);

  const m2 = dec(resp.readMessage1WriteMessage2(dec(init.writeMessage1())));
  const auth = Buffer.from(m2.auth, 'base64');
  auth[Math.floor(auth.length / 2)] ^= 0x01;
  m2.auth = auth.toString('base64');
  assert.throws(() => init.readMessage2WriteMessage3(m2));
});
