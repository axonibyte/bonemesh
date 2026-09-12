// Reads the shared transport-frame vector
// (spec/corpus/transcripts/transport-frame.json) and confirms this JS transport
// both reproduces the sealed ciphertext byte-for-byte and can open it again.
// The vector states both halves ("reproduces ct_hex and can open it"), so both
// are asserted: sealing alone would pass even if opening were broken, and
// opening alone would pass a transport that agreed with itself but not with the
// other implementations. Invoked by interop/check-transport-js.sh.
import fs from 'node:fs';
import { sealCiphertext, openCiphertext } from '../src/transport.js';

const path = process.argv[2];
if (!path) { process.stderr.write('usage: transport_check <transport-frame.json>\n'); process.exit(2); }
const { inputs, outputs } = JSON.parse(fs.readFileSync(path, 'utf8'));

let failures = 0;
const check = (name, want, got) => {
  if (got === want) { console.log(`PASS ${name}`); }
  else { console.log(`FAIL ${name}\n  got:  ${got}\n  want: ${want}`); failures++; }
};

const key = Buffer.from(inputs.key_hex, 'hex');
const seq = Number(inputs.seq);
const inner = Buffer.from(inputs.inner_plaintext_hex, 'hex');

check('ct_hex', outputs.ct_hex, sealCiphertext(key, seq, inner).toString('hex'));

const opened = openCiphertext(key, seq, Buffer.from(outputs.ct_hex, 'hex'));
if (opened === null) {
  console.log('FAIL inner_plaintext_hex\n  got:  <authentication failed>');
  failures++;
} else {
  check('inner_plaintext_hex', inputs.inner_plaintext_hex, opened.toString('hex'));
}

if (failures > 0) { process.stderr.write(`${failures} output(s) mismatched\n`); process.exit(1); }
console.log('transport frame seals and opens to the shared vector');
