// Corpus-driven interop checks for the JS port: the `framing` subcommand
// confirms the JS frame classifier reaches the same verdicts as the Java,
// Elixir, Rust, and Go implementations over spec/corpus/framing.json, and
// `messages` does the same for the message validator over
// spec/corpus/messages.json. Invoked by interop/check-framing-js.sh and
// interop/check-messages-js.sh.
import fs from 'node:fs';
import { classify, HANDSHAKE_CAP, TRANSPORT_CAP } from '../src/frame.js';
import { validate } from '../src/message.js';
import {
  split,
  MAX_SEGMENT_BYTES,
  MAX_CHUNKS,
  MAX_REASSEMBLY_BUFFER,
  MAX_CONCURRENT_REASSEMBLIES,
  REASSEMBLY_TIMEOUT_MILLIS,
} from '../src/chunk.js';

const [mode, path] = process.argv.slice(2);
if (!mode || !path) {
  process.stderr.write('usage: interop_checks <framing|messages|chunk> <corpus.json>\n');
  process.exit(2);
}
const doc = JSON.parse(fs.readFileSync(path, 'utf8'));

let failures = 0;
const report = (name, ok) => { console.log(`${ok ? 'PASS' : 'FAIL'} ${name}`); if (!ok) failures++; };

if (mode === 'framing') {
  for (const c of doc.cases) {
    const cap = c.kind === 'handshake' ? HANDSHAKE_CAP : TRANSPORT_CAP;
    const { reason } = classify(Buffer.from(c.bytes_b64, 'base64'), cap);
    const ok = c.expect === 'accept' ? reason === undefined : reason === c.reason;
    report(c.name, ok);
  }
  console.log(`framing: ${doc.cases.length} cases checked`);
} else if (mode === 'messages') {
  for (const c of doc.cases) {
    const reason = validate(c.schema, c.frame);
    const ok = c.expect === 'valid' ? reason === null : reason === c.reason;
    report(c.name, ok);
  }
  console.log(`messages: ${doc.cases.length} cases checked`);
} else if (mode === 'chunk') {
  // Two things, and the second is the one nothing else can see. First the pinned
  // §0 constants must match this implementation's -- including the three (chunk
  // count, in-flight count, timeout) that specsrc deliberately does not check,
  // because a substring search for 1024, 256 or 30000 is satisfied by any buffer
  // size already in the tree. Second, the segments this implementation produces
  // must land on exactly the byte boundaries the corpus pins, which is how all
  // seven are shown to cut in the SAME places rather than merely to cut.
  const mine = {
    max_segment_bytes: MAX_SEGMENT_BYTES,
    max_chunks: MAX_CHUNKS,
    max_reassembly_buffer: MAX_REASSEMBLY_BUFFER,
    max_concurrent_reassemblies: MAX_CONCURRENT_REASSEMBLIES,
    reassembly_timeout_millis: REASSEMBLY_TIMEOUT_MILLIS,
  };
  const pinned = doc.constants || {};
  if (Object.keys(pinned).length === 0) {
    process.stderr.write('corpus declares no chunk constants\n');
    process.exit(1);
  }
  for (const [name, want] of Object.entries(pinned)) {
    const ok = mine[name] === want;
    report(`constant ${name}${ok ? '' : `  (have ${mine[name]}, corpus pins ${want})`}`, ok);
  }
  if (!doc.split_cases || doc.split_cases.length === 0) {
    process.stderr.write('corpus has no split cases\n');
    process.exit(1);
  }
  for (const c of doc.split_cases) {
    const payload = { [c.key]: c.unit.repeat(c.times) };
    const msgs = split(doc.mid, 'a', 'b', 16, payload);
    const whole = msgs.length === 1 && 'payload' in msgs[0];
    const lengths = whole ? [] : msgs.map((m) => Buffer.byteLength(m.seg, 'utf8'));
    let ok =
      whole === c.expect_whole &&
      JSON.stringify(lengths) === JSON.stringify(c.segment_byte_lengths);
    let detail = ok
      ? ''
      : `  (whole=${whole} want ${c.expect_whole}; lengths=${JSON.stringify(lengths.slice(0, 8))} want ${JSON.stringify(c.segment_byte_lengths.slice(0, 8))})`;
    // A round-trip as the second oracle: matching lengths would not catch segments
    // that are the right size and the wrong bytes.
    if (ok && !whole) {
      const rebuilt = JSON.parse(msgs.map((m) => m.seg).join(''));
      if (JSON.stringify(rebuilt) !== JSON.stringify(payload)) {
        ok = false;
        detail = '  (segments did not rebuild the payload)';
      }
    }
    report(`${c.name}${detail}`, ok);
  }
  if (failures === 0) console.log('splitting agrees with every pinned constant and cut position');
} else {
  process.stderr.write(`unknown mode: ${mode}\n`);
  process.exit(2);
}

if (failures > 0) process.exit(1);
