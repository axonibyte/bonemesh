// BoneMesh v3 message schema validation (protocol.md §4) and inner-message
// builders. The validator mirrors the other implementations reason-for-reason
// (shared corpus: spec/corpus/messages.json).
import crypto from 'node:crypto';

export const DEFAULT_TTL = 16;

// Returns null if valid, else a reason tag. Schemas: bmx1, envelope, data, ack.
export function validate(schema, f) {
  switch (schema) {
    case 'bmx1': return validateBmx1(f);
    case 'envelope': return validateEnvelope(f);
    case 'data': return validateData(f);
    case 'ack': return validateAck(f);
    default: return 'unknown-schema';
  }
}

function validateBmx1(f) {
  if (f.t !== 'bmx1') return 'type';
  if (!isInt(f.v) || f.v !== 3) return 'version';
  if (typeof f.mesh !== 'string' || f.mesh === '') return 'empty-mesh';
  for (const k of ['e', 'k', 'n']) {
    if (!(k in f)) return 'missing-field';
    const r = base64Reason(f[k]);
    if (r) return r;
  }
  return null;
}

function validateEnvelope(f) {
  if (!isInt(f.seq)) return 'missing-field';
  if (f.seq < 0) return 'seq-range';
  if (!('ct' in f)) return 'missing-field';
  return base64Reason(f.ct);
}

function validateData(f) {
  if (f.type !== 'data') return 'type';
  const m = midReason(f.mid);
  if (m) return m;
  if (typeof f.to !== 'string') return 'missing-field';
  if (typeof f.from !== 'string') return 'missing-field';
  if (!isInt(f.ttl)) return 'missing-field';
  if (f.ttl < 1 || f.ttl > 255) return 'ttl-range';
  if (!('payload' in f)) return 'missing-field';
  return null;
}

function validateAck(f) {
  if (f.type !== 'ack') return 'type';
  return midReason(f.mid);
}

function isInt(v) {
  return typeof v === 'number' && Number.isInteger(v);
}

// Node's Buffer.from(...,'base64') is lenient, so validate strictly the way the
// other implementations' decoders do: the standard alphabet, length a multiple
// of four, padding only at the end.
const B64 = /^[A-Za-z0-9+/]*={0,2}$/;

function base64Reason(v) {
  if (typeof v !== 'string') return 'not-base64';
  if (v.length % 4 !== 0) return 'not-base64';
  if (!B64.test(v)) return 'not-base64';
  return null;
}

function midReason(v) {
  if (typeof v !== 'string' || v.length !== 32) return 'mid-format';
  for (let i = 0; i < v.length; i++) {
    const c = v[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 'mid-format';
  }
  return null;
}

// A fresh 128-bit message id as 32 lowercase-hex characters.
export function newMid() {
  return crypto.randomBytes(16).toString('hex');
}

export function data(mid, from, to, ttl, payload) {
  return { type: 'data', mid, from, to, ttl, payload };
}

export function ack(mid) {
  return { type: 'ack', mid };
}

export function echo(token) {
  return { type: 'echo', token };
}
