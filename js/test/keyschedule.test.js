// Key-schedule known-answer test. The expected values are the shared vector
// (spec/corpus/transcripts/keyschedule.json, security.md §5); reproducing them
// byte-for-byte proves the JS symmetric state agrees with Java, Elixir, Rust,
// and Go. Sequence: init; mixHash(mesh); mixKey(ss_dh); mixKey(ss_kem);
// ct1=encryptAndHash(pt1); ct2=encryptAndHash(pt2); split().
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KeySchedule } from '../src/keyschedule.js';

const hex = (h) => Buffer.from(h, 'hex');

test('reproduces the shared known-answer vector', () => {
  const V = {
    meshHex: '61636d652d70726f64',
    ssDH: '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
    ssKEM: '2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40',
    pt1: '726573706f6e6465722d61757468',
    pt2: '696e69746961746f722d61757468',
    hInit: 'ca2ab22f811afb5bca159916bd550d879ac5a6f6640d906dc05e2d9ce12c9824',
    hAfterMesh: 'f36deae782aa75db659a1d0f27b8edac65913a143bdfefa96fcc401b99c8df88',
    ckAfterDH: 'db8ea3441454c76670fd8ec86c28f1f9231b0fef58723c28a046ae457b0a107c',
    ckAfterKEM: '63e4507c23369f55dbf3fbb1d5d887c11f70b156e145db51f3aa92a02050a379',
    ct1: 'cd2faeb0160163d5ed9c8cb51f305fb9b257fbd4a06b0c371d92cbab994c',
    hAfterCT1: '316b0b3f656dddfada310c4d82595b2a9c179d68df9fe73f025da9739bef6e4c',
    ct2: 'f56b543d04ce3034e88151cc765c6de343f3039d3f72ee53e16096e3f8d9',
    hAfterCT2: 'ae83a01e2d5cf41eed8fc2df0eae17c322a920a15790454453df958df16ced76',
    i2r: 'b134801d6ec2279d03afb8ed625aaa787c6e06ceb1c11f347bad6f7432c8cb78',
    r2i: '1b29fa1fa1ef13710241c6750c08d2e3188009cc693cf1e78497ca5d97203aee',
  };
  const eq = (name, want, got) => assert.equal(got.toString('hex'), want, name);

  const s = new KeySchedule();
  eq('h_init', V.hInit, s.h);
  s.mixHash(hex(V.meshHex));
  eq('h_after_mesh', V.hAfterMesh, s.h);
  s.mixKey(hex(V.ssDH));
  eq('ck_after_dh', V.ckAfterDH, s.ck);
  s.mixKey(hex(V.ssKEM));
  eq('ck_after_kem', V.ckAfterKEM, s.ck);
  eq('ct1', V.ct1, s.encryptAndHash(hex(V.pt1)));
  eq('h_after_ct1', V.hAfterCT1, s.h);
  eq('ct2', V.ct2, s.encryptAndHash(hex(V.pt2)));
  eq('h_after_ct2', V.hAfterCT2, s.h);
  const [i2r, r2i] = s.split();
  eq('transport_key_i2r', V.i2r, i2r);
  eq('transport_key_r2i', V.r2i, r2i);
});

test('decrypt side recovers plaintext and matching transcript hash', () => {
  const mesh = hex('61636d652d70726f64');
  const ssDH = hex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
  const ssKEM = hex('2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40');
  const pt = Buffer.from('responder-auth');

  const send = new KeySchedule();
  send.mixHash(mesh); send.mixKey(ssDH); send.mixKey(ssKEM);
  const ct = send.encryptAndHash(pt);

  const recv = new KeySchedule();
  recv.mixHash(mesh); recv.mixKey(ssDH); recv.mixKey(ssKEM);
  const got = recv.decryptAndHash(ct);
  assert.deepEqual(got, pt);
  assert.deepEqual(recv.h, send.h);
});

test('decrypt rejects a tampered ciphertext', () => {
  const s = new KeySchedule();
  s.mixKey(hex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20'));
  const ct = s.encryptAndHash(Buffer.from('payload'));
  ct[0] ^= 0x01;
  const r = new KeySchedule();
  r.mixKey(hex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20'));
  assert.equal(r.decryptAndHash(ct), null);
});
