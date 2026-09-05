// Node integration test: two real JS nodes over loopback TCP complete a BMX
// handshake and deliver an application payload in each direction. Proves the
// node wires handshake, transport, and framing together correctly; live
// cross-language delivery is proven by the interop matrix.
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

test('two nodes exchange payloads over loopback', async () => {
  const root = newRoot();
  const one = await Node.start(config(root, 'one'), 0);
  const two = await Node.start(config(root, 'two'), 0);

  const oneGot = [];
  const twoGot = [];
  one.onMessage((p) => oneGot.push(p));
  two.onMessage((p) => twoGot.push(p));

  const peer = await two.connect('127.0.0.1', one.port());
  assert.equal(peer, 'one');

  assert.equal(two.send('one', { probe: 'to-one' }), true);
  await waitFor(() => oneGot.length > 0);
  assert.equal(oneGot[0].probe, 'to-one');

  // one replies to two over the same session (registered on accept).
  await waitFor(() => one.send('two', { probe: 'to-two' }));
  await waitFor(() => twoGot.length > 0);
  assert.equal(twoGot[0].probe, 'to-two');

  one.kill();
  two.kill();
});

test('three-node line relays across the middle hop', async () => {
  const root = newRoot();
  const alpha = await Node.start(config(root, 'alpha'), 0);
  const beta = await Node.start(config(root, 'beta'), 0);
  const gamma = await Node.start(config(root, 'gamma'), 0);

  const gammaGot = [];
  gamma.onMessage((p) => gammaGot.push(p));

  // Line topology: alpha <-> beta <-> gamma; alpha and gamma never connect.
  await alpha.connect('127.0.0.1', beta.port());
  await gamma.connect('127.0.0.1', beta.port());

  // Wait for discovery to give alpha a route to gamma (via beta), then delivery.
  await waitFor(() => alpha.send('gamma', { m: 'relayed' }), 15000);
  await waitFor(() => gammaGot.length > 0, 15000);
  assert.equal(gammaGot[0].m, 'relayed');
  assert.equal(alpha.routeTable().gamma, 'beta');

  alpha.kill();
  beta.kill();
  gamma.kill();
});
