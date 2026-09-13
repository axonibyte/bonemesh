// A transport-level fault tears the session down and names the reason
// (protocol.md §4 and §8, defect D20).
//
// The seq-gap injection is deterministic and exercises the ordering rule §4
// actually states; a flipped ciphertext byte takes the same branch.
//
// The malformed-frame case is this port's own bug: FrameChannel raised an error
// item while onFrameCb was set, which fell through to the (empty) waiter list and
// was queued where nothing ever drained it -- so a frame that is not one JSON
// object was silently skipped and the link carried on, where every other port
// closed.
//
// What these tests do NOT prove: that the node re-dials and recovers. That is
// tier 10's job. The claim here is narrower -- the link is torn down rather than
// kept in a state where receiveSeq can never again match what the peer sends, and
// the peer is told why.
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

// Starts alpha and beta with a live session, and records every inner message
// alpha opens so a close reason can be read off the wire rather than inferred.
async function pair(t) {
  const root = newRoot();
  const beta = await Node.start(config(root, 'beta'), 0);
  const alpha = await Node.start(config(root, 'alpha'), 0);
  t.after(() => { alpha.kill(); beta.kill(); });
  await alpha.connect('127.0.0.1', beta.port());
  await waitFor(() => alpha.links.has('beta') && beta.links.has('alpha'));

  const seen = [];
  const link = alpha.links.get('beta');
  const open = link.transport.open.bind(link.transport);
  link.transport.open = (carrier) => {
    const inner = open(carrier);
    seen.push(inner);
    return inner;
  };
  return { alpha, beta, link, seen };
}

const byes = (seen) => seen.filter((m) => m.type === 'bye');

test('an out-of-order frame tears the session down, named protocol-error', async (t) => {
  const { alpha, beta, link, seen } = await pair(t);
  link.transport.sendSeq += 1n; // skip one seq, so the next frame is a gap
  alpha.send('beta', { x: 1 });

  await waitFor(() => byes(seen).length > 0);
  assert.equal(byes(seen)[0].reason, 'protocol-error');
  await waitFor(() => !beta.links.has('alpha'));
});

test('a malformed frame in transport mode tears the session down, named protocol-error', async (t) => {
  const { beta, link, seen } = await pair(t);
  link.socket.write('{ this is not a frame\n');

  await waitFor(() => byes(seen).length > 0);
  assert.equal(byes(seen)[0].reason, 'protocol-error');
  await waitFor(() => !beta.links.has('alpha'),
    5000).catch(() => { throw new Error('beta kept a session after a malformed frame'); });
});

// §8 requires ignoring inner types a node does not recognize, so an unknown type
// is NOT a protocol error. This guards the two tests above: making every
// unparseable thing close the link would break forward compatibility.
test('an unrecognized inner type does not close the session', async (t) => {
  const { alpha, beta, link, seen } = await pair(t);
  const carrier = link.transport.seal({ type: 'quux-from-the-future', mid: 'm1' });
  link.socket.write(Buffer.from(`${JSON.stringify(carrier)}\n`));

  // Assert the absence with time allowed to pass, then prove the link is still
  // usable rather than merely still listed.
  await new Promise((r) => setTimeout(r, 750));
  assert.ok(beta.links.has('alpha'),
    'beta closed a session over an inner type it is required to ignore');
  assert.equal(byes(seen).length, 0, `beta sent a bye it should not have: ${JSON.stringify(seen)}`);

  const got = [];
  beta.onMessage((m) => got.push(m));
  alpha.send('beta', { x: 2 });
  await waitFor(() => got.length > 0).catch(() => {
    throw new Error('the link survived the unknown type but could no longer carry data');
  });
});
