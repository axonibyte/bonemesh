// Reads the shared hybrid key-agreement vector
// (spec/corpus/transcripts/handshake-agreement.json) and confirms this JS
// implementation reproduces the transcript checkpoints and transport keys.
// Sequence: mixHash(mesh, ei_pub, ki_ek, n); mixHash(er_pub); mixKey(ss_dh);
// mixHash(ct); mixKey(ss_kem); split(). Invoked by interop/check-agreement-js.sh.
import fs from 'node:fs';
import { KeySchedule } from '../src/keyschedule.js';

const path = process.argv[2];
if (!path) { process.stderr.write('usage: agreement_check <handshake-agreement.json>\n'); process.exit(2); }
const { inputs, outputs } = JSON.parse(fs.readFileSync(path, 'utf8'));
const inb = (k) => Buffer.from(inputs[k], 'hex');

let failures = 0;
const check = (name, want, got) => {
  if (got.toString('hex') === want) { console.log(`PASS ${name}`); }
  else { console.log(`FAIL ${name}\n  got:  ${got.toString('hex')}\n  want: ${want}`); failures++; }
};

const s = new KeySchedule();
s.mixHash(inb('mesh_hex'));
s.mixHash(inb('ei_pub_hex'));
s.mixHash(inb('ki_ek_hex'));
s.mixHash(inb('n_hex'));
check('h_after_msg1', outputs.h_after_msg1, s.h);

s.mixHash(inb('er_pub_hex'));
s.mixKey(inb('ss_dh_hex'));
check('ck_after_dh', outputs.ck_after_dh, s.ck);

s.mixHash(inb('kem_ct_hex'));
s.mixKey(inb('ss_kem_hex'));
check('ck_after_kem', outputs.ck_after_kem, s.ck);

// The msg-2 checkpoint is taken once both message-2 hash inputs (responder
// ephemeral and KEM ciphertext) are absorbed; mixKey does not alter h.
check('h_after_msg2_ephemerals', outputs.h_after_msg2_ephemerals, s.h);

const [i2r, r2i] = s.split();
check('transport_key_i2r', outputs.transport_key_i2r, i2r);
check('transport_key_r2i', outputs.transport_key_r2i, r2i);

if (failures > 0) { process.stderr.write(`${failures} checkpoint(s) mismatched\n`); process.exit(1); }
console.log('hybrid key agreement reproduces every shared checkpoint');
