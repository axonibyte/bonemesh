// Certificate build/verify tests (security.md §3). A cert is a mesh-root-signed
// binding of a label to an ML-DSA-65 identity key; its signed pre-image is the
// canon canonicalization of every field except "sig". The root is a throwaway
// ML-DSA-87 key generated in-test, so the suite is self-contained.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { build, verify, identityKey } from '../src/cert.js';
import { canonicalize } from '../src/canon.js';
import { mldsa65Generate } from '../src/crypto.js';

const MESH = 'acme-prod';
const NBF = 1000, EXP = 2000, NOW = 1500;

function newRoot() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ml-dsa-87');
  const pubRaw = Buffer.from(publicKey.export({ format: 'jwk' }).pub, 'base64url');
  return { pubRaw, privateKey };
}

function signedCert(label, root) {
  const { pub } = mldsa65Generate();
  const cert = build(MESH, label, pub, NBF, EXP);
  const sig = crypto.sign(null, Buffer.from(canonicalize(cert), 'utf8'), root.privateKey);
  cert.sig = sig.toString('base64');
  return cert;
}

test('verifies a valid cert', () => {
  const root = newRoot();
  assert.equal(verify(signedCert('alpha', root), root.pubRaw, MESH, NOW), null);
});

test('identity key round-trips', () => {
  const { pub } = mldsa65Generate();
  const cert = build(MESH, 'alpha', pub, NBF, EXP);
  assert.deepEqual(identityKey(cert), Buffer.from(pub));
});

test('rejects a tampered label', () => {
  const root = newRoot();
  const cert = signedCert('alpha', root);
  cert.label = 'mallory';
  assert.notEqual(verify(cert, root.pubRaw, MESH, NOW), null);
});

test('rejects a swapped identity key', () => {
  const root = newRoot();
  const cert = signedCert('alpha', root);
  cert.idk = Buffer.from(mldsa65Generate().pub).toString('base64');
  assert.notEqual(verify(cert, root.pubRaw, MESH, NOW), null);
});

test('rejects wrong mesh, expired, not-yet-valid', () => {
  const root = newRoot();
  const cert = signedCert('alpha', root);
  assert.equal(verify(cert, root.pubRaw, 'other', NOW), 'mesh mismatch');
  assert.equal(verify(cert, root.pubRaw, MESH, EXP + 1), 'certificate expired');
  assert.equal(verify(cert, root.pubRaw, MESH, NBF - 1), 'certificate not yet valid');
});

test('rejects an unsigned cert', () => {
  const { pub } = mldsa65Generate();
  const cert = build(MESH, 'alpha', pub, NBF, EXP);
  assert.equal(verify(cert, Buffer.alloc(2592), MESH, NOW), 'certificate is unsigned');
});

test('rejects a cert signed by the wrong root', () => {
  const root = newRoot();
  const other = newRoot();
  assert.notEqual(verify(signedCert('alpha', root), other.pubRaw, MESH, NOW), null);
});
