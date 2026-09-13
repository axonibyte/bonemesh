// Broadcast tests (protocol.md §6).
//
// Both halves of the D5 fix are asserted, because D5 was two bugs in one line: the
// v2 implementation iterated indirect routes only, so direct session peers were
// missed, and a node could appear among its own routes, so it broadcast to itself.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { Node } from '../src/node.js';
import { build } from '../src/cert.js';
import { canonicalize } from '../src/canon.js';
import { mldsa65Generate } from '../src/crypto.js';

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

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test('broadcast reaches every peer but never the sender', async () => {
  const root = newRoot();
  const alpha = await Node.start(config(root, 'alpha'), 0);
  const beta = await Node.start(config(root, 'beta'), 0);
  const gamma = await Node.start(config(root, 'gamma'), 0);
  try {
    const betaGot = [];
    const gammaGot = [];
    const alphaGot = [];
    beta.onMessage((p) => betaGot.push(p));
    gamma.onMessage((p) => gammaGot.push(p));
    alpha.onMessage((p) => alphaGot.push(p));

    await alpha.connect('127.0.0.1', beta.port());
    await alpha.connect('127.0.0.1', gamma.port());

    assert.equal(alpha.broadcast({ m: 'all' }), 2, 'both peers should have been handed the message');
    await waitFor(() => betaGot.length === 1 && gammaGot.length === 1);
    assert.deepEqual(betaGot[0], { m: 'all' });
    assert.deepEqual(gammaGot[0], { m: 'all' });

    // Assert the absence with time allowed to pass, and after the positives, so a
    // failure reads as "the sender got its own broadcast" rather than as a timeout.
    await sleep(500);
    assert.deepEqual(alphaGot, [], 'the sender received its own broadcast');
  } finally {
    alpha.kill(); beta.kill(); gamma.kill();
  }
});

test('broadcast gives each destination its own message id', async () => {
  // Forced, not stylistic: dedup keys on (mid, chunk index), so a shared mid would
  // have the first relay suppress every other copy, and an ack names only a mid.
  const root = newRoot();
  const alpha = await Node.start(config(root, 'alpha'), 0);
  const beta = await Node.start(config(root, 'beta'), 0);
  const gamma = await Node.start(config(root, 'gamma'), 0);
  try {
    const acked = [];
    alpha.onAck((a) => acked.push(a.mid));
    await alpha.connect('127.0.0.1', beta.port());
    await alpha.connect('127.0.0.1', gamma.port());
    assert.equal(alpha.broadcast({ m: 'all' }), 2);
    await waitFor(() => acked.length === 2);
    assert.equal(new Set(acked).size, 2, `both destinations acked the same mid: ${acked}`);
  } finally {
    alpha.kill(); beta.kill(); gamma.kill();
  }
});

test('broadcast with no peers reaches nobody', async () => {
  // The boundary: a lone node has no reachable labels, so the count is zero rather
  // than the node broadcasting to itself -- which is precisely the D5 failure.
  const root = newRoot();
  const alpha = await Node.start(config(root, 'alpha'), 0);
  try {
    const got = [];
    alpha.onMessage((p) => got.push(p));
    assert.equal(alpha.broadcast({ m: 'all' }), 0);
    await sleep(500);
    assert.deepEqual(got, [], 'a lone node broadcast to itself');
  } finally {
    alpha.kill();
  }
});
