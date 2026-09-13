// Closing a socket must not discard bytes already queued on it (D23).
//
// socket.destroy() drops the write buffer: measured on this host, 200 KB written
// and then destroyed is delivered as about 49 KB. Every bye this port sends on a
// deliberate close -- shutdown from kill(), idle from the sweep, protocol-error
// from a transport fault -- is written and then immediately followed by a close,
// so each of them rides on whether the frame happened to fit the socket buffer.
// It always did, because a bye is ~100 bytes; the margin belonged to the buffer
// rather than to the code, and a bye queued behind an in-flight data frame does
// not get that margin.
//
// The oracle is the data, not the bye: a peer that stops reading lets alpha's
// queue grow past the socket buffer, and what arrives after alpha closes is
// exactly what the close did or did not discard. Asserting on the bye alone would
// keep passing on the old behaviour, since a small frame survives destroy().
//
// What this does NOT prove: that a peer which never resumes reading is bounded.
// That is what the flush deadline is for, and it is asserted separately below.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { Node } from '../src/node.js';
import { build } from '../src/cert.js';
import { canonicalize } from '../src/canon.js';
import { mldsa65Generate } from '../src/crypto.js';

const MESH = 'acme-prod';

// These tests deliberately wedge a link and then time a close, so the node's own
// liveness sweep must not be a second thing that can close it. A paused peer sends
// no probes, so lastInbound stops advancing and the sweep would tear the link down
// on its own schedule -- which on a loaded machine can land inside the window
// under test and, worse, can remove the link before kill() is even reached, so
// kill() closes nothing and the failure looks like a missed deadline. Tunables are
// read once at node start, so this is set before any node is created and restored
// afterwards.
const PROBE_ENV = 'BONEMESH_PROBE_TIMEOUT_MS';
function withSweepDisabled(t) {
  const prior = process.env[PROBE_ENV];
  process.env[PROBE_ENV] = '600000';
  t.after(() => {
    if (prior === undefined) delete process.env[PROBE_ENV];
    else process.env[PROBE_ENV] = prior;
  });
}

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

const PAYLOAD = 'y'.repeat(16 * 1024);
// Enough queued that no socket buffer on any machine could have absorbed it, so
// what arrives after the close is a statement about the close and not about the
// kernel. Reached by looping, never by assuming a count.
const BACKED_UP = 4 * 1024 * 1024;

test('a deliberate close delivers what was already queued, rather than discarding it', async (t) => {
  withSweepDisabled(t);
  const root = newRoot();
  const beta = await Node.start(config(root, 'beta'), 0);
  const alpha = await Node.start(config(root, 'alpha'), 0);
  t.after(() => { alpha.kill(); beta.kill(); });

  const got = [];
  beta.onMessage((m) => got.push(m));
  await alpha.connect('127.0.0.1', beta.port());
  await waitFor(() => alpha.links.has('beta') && beta.links.has('alpha'));

  // Stop beta reading, so alpha's queue grows past what the kernel will take and
  // the rest sits in alpha's own write buffer -- the buffer destroy() discards.
  const betaSide = beta.links.get('alpha').socket;
  betaSide.pause();

  // Send until the pipe is demonstrably backed up rather than a fixed count: how
  // much a paused peer absorbs before anything queues is the kernel's business and
  // differs per machine. A fixed 60 messages staged the condition on the developer
  // driver and drained entirely inside a CI container, where the precondition below
  // then failed the test -- correctly, since it could not have proven anything, but
  // the staging is what needed fixing.
  const alphaSide = alpha.links.get('beta').socket;
  let sent = 0;
  while (sent < 4000 && alphaSide.writableLength < BACKED_UP) {
    alpha.send('beta', { i: sent, blob: PAYLOAD });
    sent += 1;
  }

  // Precondition, asserted before the success indicator: the writes really are
  // still queued, so a pass cannot come from everything having flushed already.
  assert.ok(alphaSide.writableLength >= BACKED_UP,
    `could not stage a backed-up socket (${alphaSide.writableLength} bytes queued after `
    + `${sent} messages); the close path is untested, so this is a failure not a pass`);
  assert.equal(got.length, 0, 'beta read messages while its socket was paused');
  assert.ok(alpha.links.has('beta'),
    'the link was gone before kill(), so kill() closed nothing and this run proved nothing');

  alpha.kill();
  betaSide.resume();

  await waitFor(() => got.length === sent, 30000).catch(() => {
    throw new Error(`the close discarded queued frames: beta received ${got.length} of ${sent}`);
  });
  assert.equal(got.length, sent);
});

test('the flush does not let a peer that never reads hold the socket open', async (t) => {
  withSweepDisabled(t);
  const root = newRoot();
  const beta = await Node.start(config(root, 'beta'), 0);
  const alpha = await Node.start(config(root, 'alpha'), 0);
  t.after(() => { alpha.kill(); beta.kill(); });

  await alpha.connect('127.0.0.1', beta.port());
  await waitFor(() => alpha.links.has('beta') && beta.links.has('alpha'));

  const alphaSide = alpha.links.get('beta').socket;
  // If the deadline is ever lost, this socket is ended-but-open and keeps the
  // event loop alive, so the suite would hang instead of failing. Force it shut
  // in cleanup: a regression should present as a red test in eight seconds, not
  // as a runner that never exits.
  t.after(() => { try { alphaSide.destroy(); } catch { /* already gone */ } });
  beta.links.get('alpha').socket.pause(); // and never resumes

  // Back the pipe up well past every buffer between here and there. An earlier
  // version of this test queued 1 MB, which the receiver's kernel buffer simply
  // absorbed: the flush then completed on its own, and the test passed just as
  // happily with the deadline deleted. Mutation testing is what caught that, and
  // it is why the volume is now established rather than assumed.
  for (let i = 0; i < 5000 && alphaSide.writableLength < BACKED_UP; i += 1) {
    alpha.send('beta', { i, blob: 'y'.repeat(64 * 1024) });
  }
  assert.ok(alphaSide.writableLength >= BACKED_UP,
    `could not stage a blocked flush (only ${alphaSide.writableLength} bytes queued); `
    + 'the deadline is untested, so this is a failure rather than a pass');

  assert.ok(alpha.links.has('beta'),
    'the link was gone before kill(), so kill() closed nothing and this run proved nothing');
  alpha.kill();

  // Precondition before the success indicator: the flush really is stuck, so a
  // close cannot be credited to it having finished normally.
  await new Promise((r) => setTimeout(r, 1000));
  assert.equal(alphaSide.destroyed, false,
    'the socket closed on its own, so this run never exercised the deadline');

  // Only the deadline can close it now. An earlier version of this assertion used
  // a 20 s window and passed with the deadline deleted, because the peer's own
  // probe-timeout sweep closed the socket instead; that alternative cause is now
  // disabled outright rather than dodged by timing, which also means the window
  // can be generous enough to survive a loaded machine.
  await waitFor(() => alphaSide.destroyed, 12000).catch(() => {
    throw new Error('a peer that never reads kept the socket open past the flush deadline');
  });
});
