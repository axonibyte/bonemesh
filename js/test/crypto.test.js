// Primitive round-trip and self-test coverage for the crypto module. These
// prove each primitive works and that the oracle fires on bad input (tampered
// AEAD, tampered signature). Cross-language agreement on these primitives is
// proven by the key-schedule KAT, the PQC interop vector, and the live matrix.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  sha256, hkdf, aeadSeal, aeadOpen,
  x25519Generate, x25519Agree,
  mlkem768Keypair, mlkem768Encapsulate, mlkem768Decapsulate,
  mldsa65Generate, mldsa65Sign, mldsa65Verify,
} from '../src/crypto.js';

test('SHA-256 known answer', () => {
  assert.equal(sha256(Buffer.from('abc')).toString('hex'),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

test('AEAD seal/open round-trip', () => {
  const key = sha256(Buffer.from('k'));
  const nonce = Buffer.alloc(12);
  const pt = Buffer.from('hello mesh');
  const ct = aeadSeal(key, nonce, Buffer.from('aad'), pt);
  const got = aeadOpen(key, nonce, Buffer.from('aad'), ct);
  assert.deepEqual(got, pt);
});

test('AEAD rejects a tampered ciphertext', () => {
  const key = sha256(Buffer.from('k'));
  const nonce = Buffer.alloc(12);
  const ct = aeadSeal(key, nonce, null, Buffer.from('hello'));
  ct[3] ^= 0x01;
  assert.equal(aeadOpen(key, nonce, null, ct), null);
});

test('AEAD rejects wrong AAD', () => {
  const key = sha256(Buffer.from('k'));
  const nonce = Buffer.alloc(12);
  const ct = aeadSeal(key, nonce, Buffer.from('aad-1'), Buffer.from('hello'));
  assert.equal(aeadOpen(key, nonce, Buffer.from('aad-2'), ct), null);
});

test('HKDF is deterministic, length-correct, and info-sensitive', () => {
  const a = hkdf(Buffer.from('salt'), Buffer.from('ikm'), Buffer.from('info'), 64);
  const b = hkdf(Buffer.from('salt'), Buffer.from('ikm'), Buffer.from('info'), 64);
  assert.equal(a.length, 64);
  assert.deepEqual(a, b);
  const c = hkdf(Buffer.from('salt'), Buffer.from('ikm'), Buffer.from('other'), 64);
  assert.notDeepEqual(a, c);
});

test('X25519 agreement is symmetric', () => {
  const a = x25519Generate();
  const b = x25519Generate();
  assert.deepEqual(x25519Agree(a.priv, b.pub), x25519Agree(b.priv, a.pub));
});

test('ML-KEM-768 encapsulate/decapsulate agree', () => {
  const { ek, dk } = mlkem768Keypair();
  const { ss, ct } = mlkem768Encapsulate(ek);
  assert.deepEqual(mlkem768Decapsulate(dk, ct), ss);
});

test('ML-DSA-65 sign/verify, and rejects tamper', () => {
  const { pub, priv } = mldsa65Generate();
  const msg = Buffer.from('transcript hash');
  const sig = mldsa65Sign(priv, msg);
  assert.equal(mldsa65Verify(pub, msg, sig), true);
  sig[10] ^= 0x01;
  assert.equal(mldsa65Verify(pub, msg, sig), false);
  assert.equal(mldsa65Verify(pub, Buffer.from('other'), mldsa65Sign(priv, msg)), false);
});
