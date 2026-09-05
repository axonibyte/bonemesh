// Reads the shared corpus (spec/corpus/canon.json) and confirms this JS
// canonicalizer reproduces each vector's expected bytes. The Java, Elixir, Rust,
// and Go implementations validate the same file, so agreement means a
// certificate signed by any of them verifies under this one. Invoked by
// interop/check-canon-js.sh; exits non-zero on any mismatch.
import fs from 'node:fs';
import { canonicalize } from '../src/canon.js';

const path = process.argv[2];
if (!path) { process.stderr.write('usage: canon_check <canon.json>\n'); process.exit(2); }
const doc = JSON.parse(fs.readFileSync(path, 'utf8'));

let failures = 0;
for (const v of doc.vectors) {
  let got;
  try {
    got = canonicalize(v.cert);
  } catch (e) {
    console.log(`FAIL ${v.name}\n  error: ${e.message}`);
    failures++;
    continue;
  }
  if (got === v.canonical) {
    console.log(`PASS ${v.name}`);
  } else {
    console.log(`FAIL ${v.name}\n  got:  ${got}\n  want: ${v.canonical}`);
    failures++;
  }
}
if (failures > 0) { process.stderr.write(`${failures} vector(s) mismatched\n`); process.exit(1); }
console.log(`all ${doc.vectors.length} canon vectors match`);
