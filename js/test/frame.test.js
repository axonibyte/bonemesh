// Frame classification tests. Verdicts mirror the shared corpus
// (spec/corpus/framing.json, protocol.md §2). Byte-for-byte agreement with the
// other implementations over that corpus is checked by bin/interop_checks.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classify, encode, HANDSHAKE_CAP, TRANSPORT_CAP } from '../src/frame.js';

const buf = (s) => Buffer.from(s, 'utf8');

test('accepts a simple object', () => {
  const { obj, reason } = classify(buf('{"t":"bmx1","v":3}\n'), HANDSHAKE_CAP);
  assert.equal(reason, undefined);
  assert.equal(obj.t, 'bmx1');
});

test('verdicts match the corpus shapes', () => {
  const cases = [
    ['no-newline', '{"a":1}', TRANSPORT_CAP, 'no-newline'],
    ['empty', '\n', TRANSPORT_CAP, 'empty'],
    ['invalid-json (garbage)', 'not json\n', TRANSPORT_CAP, 'invalid-json'],
    ['invalid-json (interior newline)', '{"a":\n1}\n', TRANSPORT_CAP, 'invalid-json'],
    ['trailing-data', '{"a":1} X\n', TRANSPORT_CAP, 'trailing-data'],
    ['not-an-object', '[1,2,3]\n', TRANSPORT_CAP, 'not-an-object'],
    ['oversize', '{"a":1}\n', 4, 'oversize'],
  ];
  for (const [name, raw, cap, want] of cases) {
    assert.equal(classify(buf(raw), cap).reason, want, name);
  }
});

test('rejects invalid UTF-8', () => {
  const raw = Buffer.concat([Buffer.from('{"a":"'), Buffer.from([0xff, 0xfe]), Buffer.from('"}\n')]);
  assert.equal(classify(raw, HANDSHAKE_CAP).reason, 'invalid-utf8');
});

test('nested object with braces inside strings scans correctly', () => {
  const { obj, reason } = classify(buf('{"a":{"b":"}]"},"c":[1,{"d":2}]}\n'), TRANSPORT_CAP);
  assert.equal(reason, undefined);
  assert.deepEqual(obj.c, [1, { d: 2 }]);
});

test('encode round-trips through classify', () => {
  const enc = encode({ t: 'bmx1', mesh: 'acme' });
  assert.equal(enc[enc.length - 1], 0x0a);
  const { obj } = classify(enc, HANDSHAKE_CAP);
  assert.equal(obj.mesh, 'acme');
});
