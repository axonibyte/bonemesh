// M5: with BONEMESH_KEYLOG set, both ends of a session write the same
// directional keys and transcript-hash label — proof the emitted keys are the
// real shared session keys and the role→direction mapping is correct (so one
// bonemesh-inspect reads a log from either end).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
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
  const nowS = Math.floor(Date.now() / 1000);
  const cert = build(MESH, label, pub, nowS - 60, nowS + 3600);
  cert.sig = crypto.sign(null, Buffer.from(canonicalize(cert), 'utf8'), root.privateKey).toString('base64');
  return { label, mesh: MESH, rootPublic: root.pubRaw, cert, idPrivate: priv };
}
const waitFor = (pred, timeoutMs = 5000) => new Promise((resolve, reject) => {
  const started = Date.now();
  const tick = () => (pred() ? resolve() : Date.now() - started > timeoutMs ? reject(new Error('timeout')) : setTimeout(tick, 20));
  tick();
});

// keylog line: "BMX3_<DIR>_TRAFFIC_<epoch> <hex th> <hex key>" -> {dir: [th, key]}
function parseKeylog(file) {
  const out = {};
  for (const ln of fs.readFileSync(file, 'utf8').trim().split('\n')) {
    const p = ln.split(' ');
    if (p.length !== 3 || !p[0].endsWith('_TRAFFIC_0')) continue;
    out[p[0].replace('BMX3_', '').replace('_TRAFFIC_0', '')] = [p[1], p[2]];
  }
  return out;
}

test('keylog emits agreeing directional keys on both ends', async (t) => {
  const root = newRoot();
  const alpha = await Node.start(config(root, 'alpha'), 0);
  const beta = await Node.start(config(root, 'beta'), 0);
  t.after(() => { alpha.kill(); beta.kill(); });

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bmklog-'));
  const fa = path.join(dir, 'a.keylog');
  const fb = path.join(dir, 'b.keylog');
  alpha.tun.keylogPath = fa;
  beta.tun.keylogPath = fb;

  await alpha.connect('127.0.0.1', beta.port());
  await waitFor(() => fs.existsSync(fa) && fs.existsSync(fb) && fs.statSync(fa).size > 0 && fs.statSync(fb).size > 0);

  const a = parseKeylog(fa);
  const b = parseKeylog(fb);
  for (const d of ['I2R', 'R2I']) {
    assert.ok(a[d] && b[d], `missing ${d} entry`);
    assert.equal(a[d][1].length, 64, `${d} key not 32-byte hex`);
    assert.equal(a[d][1], b[d][1], `${d} key disagrees between ends (role→direction mapping wrong)`);
    assert.equal(a[d][0], b[d][0], `${d} transcript-hash disagrees`);
  }
  assert.notEqual(a['I2R'][1], a['R2I'][1], 'I2R and R2I keys identical');
});
