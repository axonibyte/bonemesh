// M4 features F2 (retry/backoff) and F5 (rekey), mirroring the Go reference.
// F2 uses the public pending queue + drainRetries; F5 runs two real nodes with
// the rekey frame threshold forced low. Every started node is killed in
// t.after so `node --test` does not hang on a live handle.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { Node } from '../src/node.js';
import { build } from '../src/cert.js';
import { canonicalize } from '../src/canon.js';
import { mldsa65Generate } from '../src/crypto.js';
import * as message from '../src/message.js';

const MESH = 'acme-prod';

function newRoot() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ml-dsa-87');
  return { pubRaw: Buffer.from(publicKey.export({ format: 'jwk' }).pub, 'base64url'), privateKey };
}

function config(root, label) {
  const { pub, priv } = mldsa65Generate();
  const now = Math.floor(Date.now() / 1000);
  const cert = build(MESH, label, pub, now - 60, now + 3600);
  cert.sig = crypto.sign(null, Buffer.from(canonicalize(cert), 'utf8'), root.privateKey).toString('base64');
  return { label, mesh: MESH, rootPublic: root.pubRaw, cert, idPrivate: priv };
}

const waitFor = (predicate, timeoutMs = 5000) => new Promise((resolve, reject) => {
  const started = Date.now();
  const tick = () => {
    if (predicate()) return resolve();
    if (Date.now() - started > timeoutMs) return reject(new Error('timeout'));
    setTimeout(tick, 20);
  };
  tick();
});

test('F2: an unroutable send is queued and reported expired to the ack listener', () => {
  const root = newRoot();
  const n = new Node(config(root, 'self')); // no server; never started
  const got = [];
  n.onAck((a) => got.push(a));
  const { mid, ok } = n.sendMid('peer', { x: 1 });
  assert.equal(ok, false, 'send to an unroutable peer is not delivered now');
  assert.equal(n.pending.get('peer').length, 1, 'message queued for retry');
  // Age it past its lifetime and make it due.
  const p = n.pending.get('peer')[0];
  p.enqueuedAt = Date.now() - (n.tun.retryMaxMs + 100000);
  p.nextAt = 0;
  n.drainRetries(Date.now());
  assert.equal(n.pending.has('peer'), false, 'expired entry dropped from the queue');
  assert.equal(got.length, 1);
  assert.equal(got[0].type, 'nak');
  assert.equal(got[0].reason, 'expired');
  assert.equal(got[0].mid, mid);
});

test('F2: retry disabled (retryMaxMs=0) queues nothing', () => {
  process.env.BONEMESH_RETRY_MAX_MS = '0';
  const root = newRoot();
  const n = new Node(config(root, 'self'));
  delete process.env.BONEMESH_RETRY_MAX_MS;
  n.sendMid('peer', { x: 1 });
  assert.equal(n.pending.size, 0, 'nothing queued when retry is disabled');
});

test('F2: a queued send lands once a route appears', async (t) => {
  const root = newRoot();
  const alpha = await Node.start(config(root, 'alpha'), 0);
  const beta = await Node.start(config(root, 'beta'), 0);
  t.after(() => { alpha.kill(); beta.kill(); });
  const got = [];
  beta.onMessage((p) => got.push(p));

  // Send before any route exists — it is queued.
  const { ok } = alpha.sendMid('beta', { m: 'queued' });
  assert.equal(ok, false);
  assert.equal(alpha.pending.get('beta').length, 1);

  await alpha.connect('127.0.0.1', beta.port());
  // The heartbeat drain re-sends once beta is a neighbor.
  await waitFor(() => got.length > 0, 8000);
  assert.equal(got[0].m, 'queued');
});

test('F5: the initiator rekeys under traffic; both ends advance epoch and keep delivering', async (t) => {
  process.env.BONEMESH_REKEY_FRAMES = '6';
  const root = newRoot();
  const alpha = await Node.start(config(root, 'alpha'), 0);
  const beta = await Node.start(config(root, 'beta'), 0);
  delete process.env.BONEMESH_REKEY_FRAMES;
  t.after(() => { alpha.kill(); beta.kill(); });

  const got = [];
  beta.onMessage((p) => got.push(p));
  await alpha.connect('127.0.0.1', beta.port());

  const epoch = (n, peer) => (n.links.get(peer)?.rekeyEpoch || 0);
  await waitFor(() => epoch(alpha, 'beta') >= 1 && epoch(beta, 'alpha') >= 1, 15000);
  assert.ok(epoch(alpha, 'beta') >= 1, 'initiator never rekeyed');
  assert.ok(epoch(beta, 'alpha') >= 1, 'responder never completed a rekey');

  // Delivery must still work on the post-rekey keys.
  await waitFor(() => alpha.send('beta', { m: 'after-rekey' }), 5000);
  await waitFor(() => got.some((p) => p.m === 'after-rekey'), 5000);
});
