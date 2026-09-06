// Link registration lifecycle (protocol.md §3): a reconnect must displace and
// CLOSE the old link, and the stale link's death must never withdraw the live
// link's routes. Also checks the per-link register-time metadata and the env
// tunables seam.
//
// Timing note: the stale-death assertion runs in the window between the
// displaced socket's 'close' event and the next 1 s heartbeat, because a
// heartbeat's probe/echo would re-seed the neighbor and mask an unconditional
// withdrawal. Every node is killed via t.after so a failing assertion cannot
// leave sockets holding the test runner open.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { Node } from '../src/node.js';
import { build } from '../src/cert.js';
import { canonicalize } from '../src/canon.js';
import { mldsa65Generate } from '../src/crypto.js';
import { loadTunables } from '../src/tunables.js';

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

test('reconnect displaces the old link and its death does not withdraw routes', async (t) => {
  const root = newRoot();
  const one = await Node.start(config(root, 'one'), 0);
  const two = await Node.start(config(root, 'two'), 0);
  t.after(() => { one.kill(); two.kill(); });

  await two.connect('127.0.0.1', one.port());
  const firstLink = two.links.get('one');
  assert.ok(firstLink, 'first link registered');

  // Reconnect: displaces the first link on two's side; the displaced socket
  // must be destroyed rather than leaked.
  await two.connect('127.0.0.1', one.port());
  const secondLink = two.links.get('one');
  assert.notEqual(secondLink, firstLink, 'reconnect did not replace the link');
  await waitFor(() => firstLink.socket.destroyed, 2000);

  // Give the stale socket's 'close' event (and thus #deregister) one breath to
  // run, but stay well inside the 1 s heartbeat window so a probe/echo cannot
  // repair an unconditional withdrawal and mask the bug.
  await delay(100);
  assert.equal(two.links.get('one'), secondLink, 'live link lost');
  assert.ok(two.table.nextHop('one'), 'stale link death withdrew the live neighbor');

  // Delivery still works over the surviving link (positive control).
  const got = [];
  one.onMessage((p) => got.push(p));
  assert.equal(two.send('one', { probe: 'after-reconnect' }), true);
  await waitFor(() => got.length > 0);
  assert.equal(got[0].probe, 'after-reconnect');
});

test('register records initiator and timestamps on both ends', async (t) => {
  const root = newRoot();
  const one = await Node.start(config(root, 'one'), 0);
  const two = await Node.start(config(root, 'two'), 0);
  t.after(() => { one.kill(); two.kill(); });
  const before = Date.now();

  await two.connect('127.0.0.1', one.port());
  await waitFor(() => one.links.get('two') !== undefined, 3000);

  const dialed = two.links.get('one');
  const accepted = one.links.get('two');
  assert.equal(dialed.initiator, true, 'dialer link must record initiator=true');
  assert.equal(accepted.initiator, false, 'accepter link must record initiator=false');
  for (const l of [dialed, accepted]) {
    assert.ok(l.establishedAt >= before && l.lastInbound >= before && l.lastData >= before,
      'timestamps not initialized at register');
  }
});

test('tunables read env with pinned defaults', () => {
  process.env.BONEMESH_PROBE_TIMEOUT_MS = '1234';
  assert.equal(loadTunables().probeTimeoutMs, 1234, 'env override ignored');
  process.env.BONEMESH_PROBE_TIMEOUT_MS = 'garbage';
  assert.equal(loadTunables().probeTimeoutMs, 15000, 'unparseable env did not fall back');
  delete process.env.BONEMESH_PROBE_TIMEOUT_MS;
  const t = loadTunables();
  assert.deepEqual(
    [t.idleMs, t.retryBaseMs, t.retryCapMs, t.retryMaxMs, t.rekeyMs, t.rekeyFrames, t.rekeyTimeoutMs],
    [0, 500, 30000, 60000, 3600000, 65536, 10000],
  );
});
