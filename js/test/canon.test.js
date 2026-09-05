// JCS canonicalization tests. Vectors mirror the shared corpus
// (spec/corpus/canon.json) and security.md §11.1; byte-for-byte agreement with
// the Java, Elixir, Rust, and Go canonicalizers over that corpus (checked by
// bin/canon_check.js) is what makes the root signature portable. Escape-heavy
// expected strings are built from char codes so the source cannot smuggle a raw
// control byte in place of an escape sequence.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalize } from '../src/canon.js';

test('basic sorted keys', () => {
  const cert = { v: 3, mesh: 'acme-prod', label: 'alpha', idk: 'YWJj', nbf: 1788500000, exp: 1790000000 };
  assert.equal(canonicalize(cert),
    '{"exp":1790000000,"idk":"YWJj","label":"alpha","mesh":"acme-prod","nbf":1788500000,"v":3}');
});

test('sig field is stripped', () => {
  const cert = { v: 3, mesh: 'm', label: 'alpha', idk: 'AA==', nbf: 0, exp: 1, sig: 'SHOULD-BE-IGNORED' };
  assert.equal(canonicalize(cert), '{"exp":1,"idk":"AA==","label":"alpha","mesh":"m","nbf":0,"v":3}');
});

test('non-ascii emitted as raw UTF-8', () => {
  const cert = { v: 3, mesh: 'm', label: 'café', idk: 'AA==', nbf: 0, exp: 1 };
  assert.equal(canonicalize(cert), '{"exp":1,"idk":"AA==","label":"café","mesh":"m","nbf":0,"v":3}');
});

test('quote and backslash escaping', () => {
  // label characters: a " b \ c
  const cert = { v: 3, mesh: 'm', label: 'a"b\\c', idk: 'AA==', nbf: 0, exp: 1 };
  // escaped label token: " a \ " b \ \ c "
  const labelTok = String.fromCharCode(0x22, 0x61, 0x5c, 0x22, 0x62, 0x5c, 0x5c, 0x63, 0x22);
  assert.equal(canonicalize(cert),
    `{"exp":1,"idk":"AA==","label":${labelTok},"mesh":"m","nbf":0,"v":3}`);
});

test('control characters use short and \\u escapes', () => {
  const label = 'a' + String.fromCharCode(0x08, 0x09, 0x0a, 0x0c, 0x0d, 0x01) + 'b';
  const cert = { label };
  // expected token: " a \b \t \n \f \r  b "
  const esc = String.fromCharCode(0x5c); // backslash
  const labelTok = `"a${esc}b${esc}t${esc}n${esc}f${esc}r${esc}u0001b"`;
  assert.equal(canonicalize(cert), `{"label":${labelTok}}`);
});

test('negative integer is rejected', () => {
  assert.throws(() => canonicalize({ nbf: -1 }));
});

test('non-integer number is rejected', () => {
  assert.throws(() => canonicalize({ v: 3.5 }));
});

test('boolean value is rejected', () => {
  assert.throws(() => canonicalize({ ok: true }));
});

test('nested objects are sorted independently', () => {
  assert.equal(canonicalize({ z: 1, a: { y: 2, b: 3 } }), '{"a":{"b":3,"y":2},"z":1}');
});
