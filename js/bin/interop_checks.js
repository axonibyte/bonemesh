// Corpus-driven interop checks for the JS port: the `framing` subcommand
// confirms the JS frame classifier reaches the same verdicts as the Java,
// Elixir, Rust, and Go implementations over spec/corpus/framing.json, and
// `messages` does the same for the message validator over
// spec/corpus/messages.json. Invoked by interop/check-framing-js.sh and
// interop/check-messages-js.sh.
import fs from 'node:fs';
import { classify, HANDSHAKE_CAP, TRANSPORT_CAP } from '../src/frame.js';
import { validate } from '../src/message.js';

const [mode, path] = process.argv.slice(2);
if (!mode || !path) { process.stderr.write('usage: interop_checks <framing|messages> <corpus.json>\n'); process.exit(2); }
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
} else {
  process.stderr.write(`unknown mode: ${mode}\n`);
  process.exit(2);
}

if (failures > 0) process.exit(1);
