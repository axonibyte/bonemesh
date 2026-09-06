// M3 node features (protocol.md §3, §7): the simultaneous-dial tiebreak (F1),
// probe-timeout death (F3), idle teardown (F4), and ack/NAK emission with
// per-hop failure attribution (F6 / defect D4). F1/F3/F4 are exercised at the
// method level for determinism (no dependence on the 1 s heartbeat); F6 uses
// real nodes. Every started node is killed in t.after so `node --test` does not
// hang on a live handle.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import net from 'node:net';
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
const waitFor = (predicate, timeoutMs = 15000) => new Promise((resolve, reject) => {
  const started = Date.now();
  const tick = () => {
    if (predicate()) return resolve();
    if (Date.now() - started > timeoutMs) return reject(new Error('timeout'));
    setTimeout(tick, 20);
  };
  tick();
});

test('F1 both ends of a simultaneous dial converge on the lower node’s session', async (t) => {
  // alpha and beta each dial the other. The real #register tiebreak on both
  // ends must drop one session so each keeps exactly one link, and both keep
  // the session the lexicographically-lower node (alpha) initiated: alpha keeps
  // its own dial (initiator=true), beta keeps the one it accepted (initiator=false).
  const root = newRoot();
  const alpha = await Node.start(config(root, 'alpha'), 0);
  const beta = await Node.start(config(root, 'beta'), 0);
  t.after(() => { alpha.kill(); beta.kill(); });

  await alpha.connect('127.0.0.1', beta.port());
  await beta.connect('127.0.0.1', alpha.port());

  // Let the losing sessions be dropped, then confirm convergence.
  await waitFor(() => alpha.links.size === 1 && beta.links.size === 1
    && alpha.links.has('beta') && beta.links.has('alpha'));
  assert.equal(alpha.links.get('beta').initiator, true, 'alpha (lower) must keep its own-initiated session');
  assert.equal(beta.links.get('alpha').initiator, false, 'beta (higher) must keep the session it accepted');

  // The surviving session still delivers both ways.
  const got = [];
  beta.onMessage((p) => got.push(p));
  await waitFor(() => alpha.send('beta', { m: 'converged' }));
  await waitFor(() => got.length > 0);
  assert.equal(got[0].m, 'converged');
});

test('F3 probe-timeout tears down a silent link; a fresh one is kept', () => {
  const node = new Node({ label: 'self', mesh: MESH });
  node.tun.probeTimeoutMs = 100;
  node.tun.idleMs = 0;
  const sock = new net.Socket();
  const link = { socket: sock, initiator: true, lastInbound: Date.now(), lastData: Date.now() };
  node.links.set('peer', link);
  node.table.observeNeighbor('peer', 1);

  node.sweepLink(Date.now(), 'peer', link); // fresh: kept
  assert.ok(node.links.has('peer'), 'a fresh link was wrongly torn down');

  link.lastInbound = Date.now() - 5000; // silent past the timeout
  node.sweepLink(Date.now(), 'peer', link);
  assert.ok(!node.links.has('peer'), 'a probe-timed-out link was not torn down');
  assert.ok(!node.table.nextHop('peer'), 'neighbor not withdrawn on probe-timeout death');
});

test('F4 idle teardown fires only when enabled', () => {
  const enabled = new Node({ label: 'self', mesh: MESH });
  enabled.tun.probeTimeoutMs = 1_000_000;
  enabled.tun.idleMs = 100;
  const l1 = { socket: new net.Socket(), initiator: true, lastInbound: Date.now(), lastData: Date.now() - 5000 };
  enabled.links.set('peer', l1);
  enabled.table.observeNeighbor('peer', 1);
  enabled.sweepLink(Date.now(), 'peer', l1);
  assert.ok(!enabled.links.has('peer'), 'idle link not torn down when enabled');

  const disabled = new Node({ label: 'self', mesh: MESH });
  disabled.tun.probeTimeoutMs = 1_000_000;
  disabled.tun.idleMs = 0;
  const l2 = { socket: new net.Socket(), initiator: true, lastInbound: Date.now(), lastData: Date.now() - 5000 };
  disabled.links.set('peer', l2);
  disabled.table.observeNeighbor('peer', 1);
  disabled.sweepLink(Date.now(), 'peer', l2);
  assert.ok(disabled.links.has('peer'), 'idle teardown fired though disabled (idleMs=0)');
});

test('F6 ack: a delivered message is acknowledged to the origin', async (t) => {
  const root = newRoot();
  const alpha = await Node.start(config(root, 'alpha'), 0);
  const beta = await Node.start(config(root, 'beta'), 0);
  t.after(() => { alpha.kill(); beta.kill(); });

  const acks = [];
  alpha.onAck((a) => acks.push(a));
  await alpha.connect('127.0.0.1', beta.port());

  let mid;
  await waitFor(() => { const r = alpha.sendMid('beta', { m: 'hi' }); mid = r.mid; return r.ok; });
  await waitFor(() => acks.length > 0);
  assert.equal(acks[0].type, 'ack');
  assert.equal(acks[0].mid, mid, 'ack mid must match the sent mid');
});

test('F6/D4 NAK names the failing relay, not the destination', async (t) => {
  const root = newRoot();
  const alpha = await Node.start(config(root, 'alpha'), 0);
  const beta = await Node.start(config(root, 'beta'), 0);
  const gamma = await Node.start(config(root, 'gamma'), 0);
  t.after(() => { alpha.kill(); beta.kill(); gamma.kill(); });

  await alpha.connect('127.0.0.1', beta.port());
  await gamma.connect('127.0.0.1', beta.port());
  await waitFor(() => alpha.routeTable().gamma === 'beta');

  const acks = [];
  alpha.onAck((a) => acks.push(a));
  const { mid } = alpha.sendWithTtl('gamma', { m: 'doomed' }, 1); // beta exhausts ttl
  await waitFor(() => acks.length > 0);
  assert.equal(acks[0].type, 'nak');
  assert.equal(acks[0].hop, 'beta', 'NAK must name the relay beta, not the destination gamma (the D4 bug)');
  assert.equal(acks[0].reason, 'ttl');
  assert.equal(acks[0].mid, mid);
});
