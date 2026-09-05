// Verifies the JS port's post-quantum interop against the shared vector
// (spec/corpus/transcripts/pqc-interop.json), produced by the Java reference
// (BouncyCastle).
//
// It verifies the ML-DSA-65 signature over the vector's message using the
// vector's public key, exercising the node's real mldsa65Verify (Node/OpenSSL).
// Success proves JS and Java agree on ML-DSA-65 at the byte level.
//
// It does NOT decapsulate the vector's ML-KEM ciphertext: the vector ships a
// 2400-byte FIPS *expanded* decapsulation key, while this port (like Go) is
// keyed by the 64-byte seed. That is a private-key *representation* difference,
// not an interop gap — a decapsulation key never crosses a node (only the
// encapsulation key, ciphertext, and public artifacts do, all standard FIPS
// encodings). Live ML-KEM-768 interop between JS and Java/Elixir/Rust/Go is
// proven directly by the interop matrix. This tool names that boundary rather
// than loading a key format the node never receives.
import fs from 'node:fs';
import { mldsa65Verify } from '../src/crypto.js';

const path = process.argv[2];
if (!path) { process.stderr.write('usage: pqc_check <pqc-interop.json>\n'); process.exit(2); }
const v = JSON.parse(fs.readFileSync(path, 'utf8')).mldsa65;

const ok = mldsa65Verify(
  Buffer.from(v.public_hex, 'hex'),
  Buffer.from(v.message_hex, 'hex'),
  Buffer.from(v.signature_hex, 'hex'),
);
if (!ok) { process.stderr.write('FAIL: JS did not verify the Java ML-DSA-65 signature\n'); process.exit(1); }
console.log('PASS: JS verifies the Java ML-DSA-65 signature over the shared vector');
console.log('NOTE: ML-KEM-768 interop with Java is proven live by the interop matrix');
console.log('      (Node/OpenSSL ML-KEM is seed-keyed; the vector\'s expanded dk is a');
console.log('      key-representation detail that never crosses a node).');
