// Reads the shared key-log vector (spec/corpus/keylog.json) and confirms this
// implementation can open a key-logged capture.
//
// security.md §8 pins one implementation-neutral key-log format precisely so that a
// single inspector reads a log written by a node in any language. That claim needs
// agreement in BOTH directions: emitting lines your own reader accepts is not
// enough. This checks the reading half against a committed capture the Java
// reference produced. The writing half is covered by each port's own key-log tests
// and, live and cross-language, by interop tier 10.
//
// Invoked by interop/check-keylog-js.sh.
import fs from 'node:fs';
import { openCiphertext } from '../src/transport.js';

const LABEL = /^BMX3_(I2R|R2I)_TRAFFIC_(\d+)$/;

// '#' lines are comments; an unknown label shape is ignored rather than fatal, so
// a future label is not a breaking change.
function parseKeylog(lines) {
  const keys = new Map();
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const parts = line.split(/\s+/);
    if (parts.length !== 3) continue;
    const m = LABEL.exec(parts[0]);
    if (!m) continue;
    const key = Buffer.from(parts[2], 'hex');
    if (key.length !== 32) continue;
    keys.set(`${m[1].toLowerCase()}:${Number(m[2])}`, key);
  }
  return keys;
}

const path = process.argv[2];
if (!path) { process.stderr.write('usage: keylog_check <keylog.json>\n'); process.exit(2); }
const doc = JSON.parse(fs.readFileSync(path, 'utf8'));
const capture = doc.capture ?? [];
const expected = doc.expected ?? [];
if (capture.length === 0 || capture.length !== expected.length) {
  process.stderr.write(`vector malformed: ${capture.length} capture, ${expected.length} expected\n`);
  process.exit(1);
}
const keys = parseKeylog(doc.keylog ?? []);
if (keys.size === 0) { process.stderr.write('no usable key-log entries in the vector\n'); process.exit(1); }

const canon = (v) => JSON.stringify(v, Object.keys(flatten(v)).sort());
function flatten(v) { const o = {}; (function walk(x){ if (x && typeof x === 'object' && !Array.isArray(x)) for (const k of Object.keys(x)) { o[k] = 1; walk(x[k]); } })(v); return o; }

let failures = 0;
for (let i = 0; i < capture.length; i++) {
  const dir = capture[i].dir;
  const seq = Number(capture[i].frame.seq);
  const ct = Buffer.from(capture[i].frame.ct, 'base64');
  const key = keys.get(`${dir}:${Number(expected[i].epoch)}`);
  if (!key) { console.log(`FAIL frame ${i}: no key for ${dir} epoch ${expected[i].epoch}`); failures++; continue; }
  const pt = openCiphertext(key, seq, ct);
  if (pt === null) { console.log(`FAIL frame ${i}: the logged ${dir} key did not open it`); failures++; continue; }
  const got = JSON.parse(pt.toString('utf8'));
  // Compare structurally, not as text: key order is not part of the contract.
  if (canon(got) === canon(expected[i].inner)) console.log(`PASS frame ${i} (${dir} seq ${seq})`);
  else { console.log(`FAIL frame ${i}\n  got:  ${canon(got)}\n  want: ${canon(expected[i].inner)}`); failures++; }
}

// Self-test the oracle: a ciphertext no key seals must be refused, or a checker
// that reported success for everything would look identical to this one.
if (openCiphertext([...keys.values()][0], 0, Buffer.alloc(32)) !== null) {
  console.log('FAIL self-test: an unopenable frame was accepted'); failures++;
} else console.log('PASS self-test: an unopenable frame is refused');

if (failures > 0) { process.stderr.write(`${failures} key-log frame(s) failed\n`); process.exit(1); }
console.log('every captured frame opens with its logged key and reproduces the vector');
