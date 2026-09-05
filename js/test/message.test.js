// Message-schema validation tests. Reason tags mirror the shared corpus
// (spec/corpus/messages.json, protocol.md §4). Byte-for-byte agreement over the
// corpus is checked by bin/interop_checks.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validate, data, ack, newMid, DEFAULT_TTL } from '../src/message.js';

const MID = '0123456789abcdef0123456789abcdef';

test('schema verdicts', () => {
  const cases = [
    ['bmx1', { t: 'bmx1', v: 3, mesh: 'm', e: 'AA==', k: 'AA==', n: 'AA==' }, null],
    ['bmx1', { t: 'nope', v: 3, mesh: 'm', e: 'AA==', k: 'AA==', n: 'AA==' }, 'type'],
    ['bmx1', { t: 'bmx1', v: 2, mesh: 'm', e: 'AA==', k: 'AA==', n: 'AA==' }, 'version'],
    ['bmx1', { t: 'bmx1', v: 3, mesh: '', e: 'AA==', k: 'AA==', n: 'AA==' }, 'empty-mesh'],
    ['bmx1', { t: 'bmx1', v: 3, mesh: 'm', k: 'AA==', n: 'AA==' }, 'missing-field'],
    ['bmx1', { t: 'bmx1', v: 3, mesh: 'm', e: '!!!', k: 'AA==', n: 'AA==' }, 'not-base64'],

    ['envelope', { seq: 0, ct: 'AA==' }, null],
    ['envelope', { ct: 'AA==' }, 'missing-field'],
    ['envelope', { seq: -1, ct: 'AA==' }, 'seq-range'],
    ['envelope', { seq: 0, ct: '@@@@' }, 'not-base64'],

    ['data', { type: 'data', mid: MID, to: 'b', from: 'a', ttl: 16, payload: {} }, null],
    ['data', { type: 'x', mid: MID, to: 'b', from: 'a', ttl: 16, payload: {} }, 'type'],
    ['data', { type: 'data', mid: 'short', to: 'b', from: 'a', ttl: 16, payload: {} }, 'mid-format'],
    ['data', { type: 'data', mid: MID, from: 'a', ttl: 16, payload: {} }, 'missing-field'],
    ['data', { type: 'data', mid: MID, to: 'b', from: 'a', ttl: 0, payload: {} }, 'ttl-range'],
    ['data', { type: 'data', mid: MID, to: 'b', from: 'a', ttl: 256, payload: {} }, 'ttl-range'],

    ['ack', { type: 'ack', mid: MID }, null],
    ['ack', { type: 'nack', mid: MID }, 'type'],
    ['ack', { type: 'ack', mid: 'NOTHEX0000000000000000000000000x' }, 'mid-format'],

    ['mystery', {}, 'unknown-schema'],
  ];
  for (const [schema, msg, want] of cases) {
    assert.equal(validate(schema, msg), want, `${schema} ${JSON.stringify(msg)}`);
  }
});

test('builders produce valid messages', () => {
  assert.equal(validate('data', data(newMid(), 'a', 'b', DEFAULT_TTL, { k: 'v' })), null);
  assert.equal(validate('ack', ack(newMid())), null);
});

test('newMid is well-formed and unique', () => {
  const seen = new Set();
  for (let i = 0; i < 1000; i++) {
    const id = newMid();
    assert.match(id, /^[0-9a-f]{32}$/);
    assert.equal(seen.has(id), false);
    seen.add(id);
  }
});
