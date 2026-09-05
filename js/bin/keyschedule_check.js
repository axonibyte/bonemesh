// Reads the shared key-schedule vector
// (spec/corpus/transcripts/keyschedule.json) and confirms this JS symmetric
// state reproduces every output. Agreement with Java, Elixir, Rust, and Go over
// this file means a handshake driven by any of them derives the same transport
// keys. Invoked by interop/check-keyschedule-js.sh.
import fs from 'node:fs';
import { KeySchedule } from '../src/keyschedule.js';

const path = process.argv[2];
if (!path) { process.stderr.write('usage: keyschedule_check <keyschedule.json>\n'); process.exit(2); }
const { inputs, outputs } = JSON.parse(fs.readFileSync(path, 'utf8'));
const hex = (h) => Buffer.from(h, 'hex');

let failures = 0;
const check = (name, want, got) => {
  if (got.toString('hex') === want) { console.log(`PASS ${name}`); }
  else { console.log(`FAIL ${name}\n  got:  ${got.toString('hex')}\n  want: ${want}`); failures++; }
};

const s = new KeySchedule();
check('h_init', outputs.h_init, s.h);
s.mixHash(hex(inputs.mesh_hex));
check('h_after_mesh', outputs.h_after_mesh, s.h);
s.mixKey(hex(inputs.ss_dh_hex));
check('ck_after_dh', outputs.ck_after_dh, s.ck);
s.mixKey(hex(inputs.ss_kem_hex));
check('ck_after_kem', outputs.ck_after_kem, s.ck);
check('ct1', outputs.ct1_hex, s.encryptAndHash(hex(inputs.plaintext1_hex)));
check('h_after_ct1', outputs.h_after_ct1, s.h);
check('ct2', outputs.ct2_hex, s.encryptAndHash(hex(inputs.plaintext2_hex)));
check('h_after_ct2', outputs.h_after_ct2, s.h);
const [i2r, r2i] = s.split();
check('transport_key_i2r', outputs.transport_key_i2r, i2r);
check('transport_key_r2i', outputs.transport_key_r2i, r2i);

if (failures > 0) { process.stderr.write(`${failures} output(s) mismatched\n`); process.exit(1); }
console.log('key schedule reproduces every shared output');
