// Splitting and reassembly tests (protocol.md §6.1).
//
// Two groups. The first pins the format: a small payload travels whole, a large
// one splits and rebuilds byte-identically, segments are text rather than Base64,
// and cuts land on character boundaries even when every character is multi-byte.
// That last one matters more here than anywhere else: a JavaScript string is
// UTF-16 and its .length is not its byte count, so a port that reasoned in
// characters would emit over-cap segments on any non-ASCII payload.
//
// The second pins the bounds, which is the half that had no coverage anywhere
// before 3.3.0 and where the defect was. Each asserts that a hostile message is
// refused AND that refusing it released whatever it claimed: a reassembler that
// rejects a segment but keeps its partial forever is still a leak, and the
// refusal alone cannot show that.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  split,
  Reassembler,
  MAX_SEGMENT_BYTES,
  MAX_CHUNKS,
  MAX_REASSEMBLY_BUFFER,
  MAX_CONCURRENT_REASSEMBLIES,
  REASSEMBLY_TIMEOUT_MILLIS,
} from '../src/chunk.js';
import { data, dataSegment, validate } from '../src/message.js';

const MID = '0123456789abcdef0123456789abcdef';
const blob = (n) => Array.from({ length: n }, (_, i) => String.fromCharCode(97 + (i % 26))).join('');
const seg = (mid, i, n, s) => dataSegment(mid, 'a', 'b', 16, i, n, s);

// ---- format ----

test('a small payload travels whole', () => {
  const payload = { line: 'hello' };
  const msgs = split(MID, 'a', 'b', 16, payload);
  assert.equal(msgs.length, 1);
  assert.ok(!('chunk' in msgs[0]), 'a whole message must not carry chunk');
  assert.ok(!('seg' in msgs[0]), 'a whole message must not carry seg');
  assert.deepEqual(msgs[0].payload, payload);
});

test('a large payload splits and reassembles', () => {
  const payload = { blob: blob(120000) };
  const msgs = split(MID, 'a', 'b', 16, payload);
  assert.ok(msgs.length > 1, 'large payload was not split');
  msgs.forEach((m, i) => {
    assert.equal(validate('data', m), null, `segment ${i} failed the data schema`);
    assert.ok(!('payload' in m), `segment ${i} carries a payload`);
    assert.equal(typeof m.seg, 'string');
    assert.ok(
      Buffer.byteLength(m.seg, 'utf8') <= MAX_SEGMENT_BYTES,
      `segment ${i} is over the pinned maximum`,
    );
  });

  const r = new Reassembler();
  for (const m of msgs.slice(0, -1)) assert.equal(r.offer(m, 0), undefined, 'completed early');
  assert.deepEqual(r.offer(msgs.at(-1), 0), payload);
  assert.equal(r.inFlight(), 0, 'a completed message stayed buffered');
  assert.equal(r.buffered(), 0, 'a completed message stayed counted');
});

test('segments are text, not base64', () => {
  // decision #25: a segment is a slice of the payload's JSON text, so it stays
  // readable through the key-log inspector. Concatenation must reproduce the
  // serialized payload with no decode step.
  const payload = { blob: blob(60000) };
  const msgs = split(MID, 'a', 'b', 16, payload);
  assert.equal(msgs.map((m) => m.seg).join(''), JSON.stringify(payload));
  assert.ok(msgs[0].seg.startsWith('{'), 'the first segment should open the payload JSON');
});

test('cuts land on character boundaries', () => {
  // Every character is 3 UTF-8 bytes, so 24000 divides unevenly and a naive byte
  // cut would split one. A port counting UTF-16 units instead of bytes would also
  // emit segments well over the cap, which the byteLength assertion catches.
  const payload = { cjk: '日'.repeat(40000) };
  const msgs = split(MID, 'a', 'b', 16, payload);
  assert.ok(msgs.length > 1);
  for (const [i, m] of msgs.entries()) {
    assert.ok(
      Buffer.byteLength(m.seg, 'utf8') <= MAX_SEGMENT_BYTES,
      `segment ${i} is over the pinned maximum`,
    );
    assert.ok(!m.seg.includes('�'), `segment ${i} contains a replacement char: a cut split a character`);
  }
  const r = new Reassembler();
  let got;
  for (const m of msgs) got = r.offer(m, 0);
  assert.deepEqual(got, payload);
});

test('out-of-order segments still reassemble', () => {
  const payload = { blob: blob(120000) };
  const msgs = split(MID, 'a', 'b', 16, payload);
  const r = new Reassembler();
  let got;
  for (const m of [...msgs].reverse()) got = r.offer(m, 0);
  assert.deepEqual(got, payload);
});

// ---- bounds ----

test('an absurd chunk count is refused before allocating', () => {
  // The Java reference sized its buffer on the peer's n before validating it, so
  // one frame claiming two billion segments exhausted the heap. Both oracles
  // matter: the offer is refused, AND nothing was retained.
  const r = new Reassembler();
  for (const n of [Number.MAX_SAFE_INTEGER, 2000000000, 1000000, MAX_CHUNKS + 1]) {
    assert.equal(r.offer(seg(MID, 0, n, 'x'), 0), undefined, `accepted n=${n}`);
    assert.equal(r.inFlight(), 0, `n=${n} was buffered anyway`);
    assert.equal(r.buffered(), 0, `n=${n} was counted anyway`);
  }
  // The boundary itself is legal, so this is a bound and not a blanket ban.
  r.offer(seg(MID, 0, MAX_CHUNKS, 'x'), 0);
  assert.equal(r.inFlight(), 1, 'the maximum legal chunk count was refused');
});

test('malformed chunk metadata is refused', () => {
  const r = new Reassembler();
  const bad = [
    { ...seg(MID, 0, 3, 'x'), chunk: 'not-an-object' },
    { ...seg(MID, 0, 3, 'x'), chunk: null },
    { ...seg(MID, 0, 3, 'x'), chunk: [0, 3] },
    { ...seg(MID, 0, 3, 'x'), chunk: { i: 'zero', n: 3 } },
    { ...seg(MID, 0, 3, 'x'), chunk: { i: 0 } },
    { ...seg(MID, 0, 3, 'x'), chunk: { i: 0.5, n: 3 } },
    seg(MID, 3, 3, 'x'),
    seg(MID, -1, 3, 'x'),
    seg(MID, 0, 0, 'x'),
  ];
  for (const [k, m] of bad.entries()) {
    assert.equal(r.offer(m, 0), undefined, `case ${k}: accepted malformed chunk`);
    assert.equal(r.inFlight(), 0, `case ${k}: malformed chunk was buffered`);
  }
});

test('a segment without its slice is refused', () => {
  const r = new Reassembler();
  const m = seg(MID, 0, 3, 'x');
  delete m.seg;
  assert.equal(r.offer(m, 0), undefined);
  assert.equal(r.inFlight(), 0);
});

test('a whole message claiming to be a segment is not delivered', () => {
  const r = new Reassembler();
  const m = seg(MID, 0, 1, '{"a":1}');
  assert.equal(r.offer(m, 0), undefined, 'delivered a fragment as a whole payload');
  assert.equal(validate('data', m), 'payload-or-seg');
});

test('a message carrying both payload and segment is not delivered', () => {
  // Found by mutation in the Rust port, then fixed in all seven: the whole-message
  // path returned the payload whenever one was present, so a message contradicting
  // itself was delivered. The schema rejects it, but the schema is not on the wire
  // path (decision #27), so the reassembler has to refuse it too.
  const r = new Reassembler();
  assert.equal(r.offer({ ...data(MID, 'a', 'b', 16, { x: 1 }), seg: '{' }, 0), undefined);
  assert.equal(r.offer({ ...seg(MID, 0, 1, '{'), payload: { x: 1 } }, 0), undefined);
});

test('a non-object chunk is refused even with a payload', () => {
  // The distinguishing input: a garbage chunk on a message that DOES carry a
  // payload. Java conflated "chunk absent" with "chunk unparseable" and delivered
  // it; nothing tested the case, which is how that survived.
  const r = new Reassembler();
  for (const garbage of ['1/3', 7, [], true]) {
    const m = { ...data(MID, 'a', 'b', 16, { x: 1 }), chunk: garbage };
    assert.equal(r.offer(m, 0), undefined, `delivered a message whose chunk was ${JSON.stringify(garbage)}`);
    assert.notEqual(validate('data', m), null, 'the schema should reject it too');
  }
});

test('the byte budget counts UTF-8 bytes, not UTF-16 units', () => {
  // Found by mutation: the budget test used an ASCII segment, where .length and
  // byteLength agree, so measuring in UTF-16 units passed. A 3-byte character
  // separates them -- 8000 of them are 24000 bytes but only 8000 units.
  const r = new Reassembler();
  const seg8000 = '日'.repeat(8000);
  assert.equal(Buffer.byteLength(seg8000, 'utf8'), 24000);
  assert.equal(seg8000.length, 8000);
  r.offer(seg(MID, 0, MAX_CHUNKS, seg8000), 0);
  assert.equal(r.buffered(), 24000, 'the budget counted UTF-16 units, not bytes');
});

test('concurrent reassemblies are bounded', () => {
  const r = new Reassembler();
  for (let k = 0; k < MAX_CONCURRENT_REASSEMBLIES; k++) {
    r.offer(seg(k.toString(16).padStart(32, '0'), 0, 4, 'x'), 0);
  }
  assert.equal(r.inFlight(), MAX_CONCURRENT_REASSEMBLIES);
  r.offer(seg('f'.repeat(32), 0, 4, 'x'), 0);
  assert.equal(r.inFlight(), MAX_CONCURRENT_REASSEMBLIES, 'the bound was exceeded');
});

test('buffered bytes are bounded', () => {
  // The in-flight bound (256) is reached long before 16 MiB of segments can be
  // spread across separate message ids, so the byte budget is only reachable
  // inside one message: 1024 segments of 24000 bytes is 24.5 MB, over the ceiling.
  const r = new Reassembler();
  const full = 'y'.repeat(MAX_SEGMENT_BYTES);
  let accepted = 0;
  for (let i = 0; i < MAX_CHUNKS; i++) {
    r.offer(seg(MID, i, MAX_CHUNKS, full), 0);
    if (r.inFlight() === 0) break; // abandoned: the budget refused it
    accepted++;
    assert.ok(r.buffered() <= MAX_REASSEMBLY_BUFFER, 'the buffer maximum was exceeded');
  }
  assert.equal(
    accepted,
    Math.floor(MAX_REASSEMBLY_BUFFER / MAX_SEGMENT_BYTES),
    'the message should be abandoned on the first segment that would not fit',
  );
  assert.equal(r.inFlight(), 0, 'the abandoned message was retained');
  assert.equal(r.buffered(), 0, 'abandoning did not return its bytes');
});

test('stale partials are swept', () => {
  const r = new Reassembler();
  r.offer(seg(MID, 0, 3, 'x'), 1000);
  assert.equal(r.inFlight(), 1);
  r.offer(seg(MID, 1, 3, 'y'), 1000 + REASSEMBLY_TIMEOUT_MILLIS - 1);
  assert.equal(r.inFlight(), 1, 'swept too early');
  r.offer(seg('1'.repeat(32), 0, 3, 'z'), 1000 + REASSEMBLY_TIMEOUT_MILLIS);
  assert.equal(r.inFlight(), 1, 'the stale partial was not swept');
  assert.equal(r.buffered(), 1, 'swept bytes were not returned to the budget');
});

test('an oversized payload fails at the origin', () => {
  // §6.1: an origin whose payload no conforming destination would reassemble is
  // told locally rather than emitting it.
  assert.throws(() => split(MID, 'a', 'b', 16, { blob: blob(MAX_REASSEMBLY_BUFFER + 1) }));
});
