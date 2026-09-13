// BoneMesh v3 message schema validation (protocol.md §4) and inner-message
// builders. The validator mirrors the other implementations reason-for-reason
// (shared corpus: spec/corpus/messages.json).
import crypto from 'node:crypto';

export const DEFAULT_TTL = 16;

// chunk.js imports the builders below and this imports its bound back, which is a
// module cycle. It is safe here and only here: both directions are read inside
// function bodies rather than at module evaluation, so ESM's live bindings are
// resolved by the time either is called. Do not move either use to top level.
import { MAX_CHUNKS } from './chunk.js';

// Returns null if valid, else a reason tag. Schemas: bmx1, envelope, data, ack,
// nak, bye.
export function validate(schema, f) {
  switch (schema) {
    case 'bmx1': return validateBmx1(f);
    case 'bmx2': return validateBmx2(f);
    case 'bmx3': return validateBmx3(f);
    case 'disco': return validateDisco(f);
    case 'probe': return validateTokenCarrier(f, 'probe');
    case 'echo': return validateTokenCarrier(f, 'echo');
    case 'rekey': return validateRekey(f);
    case 'envelope': return validateEnvelope(f);
    case 'data': return validateData(f);
    case 'ack': return validateAck(f);
    case 'nak': return validateNak(f);
    case 'bye': return validateBye(f);
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

// Handshake messages 2 and 3 (security.md §4). Both carry one sealed `auth` member
// rather than separate cert and sig.
function validateBmx2(f) {
  if (f.t !== 'bmx2') return 'type';
  return requireBase64(f, ['e', 'ct', 'auth']);
}

function validateBmx3(f) {
  if (f.t !== 'bmx3') return 'type';
  return requireBase64(f, ['auth']);
}

// Route advertisement (protocol.md §4.2, §6). An empty advertisement is {}, never [].
function validateDisco(f) {
  if (f.type !== 'disco') return 'type';
  if (!('routes' in f)) return 'missing-field';
  const r = f.routes;
  if (r === null || typeof r !== 'object' || Array.isArray(r)) return 'routes-format';
  for (const cost of Object.values(r)) {
    if (!isInt(cost) || cost < 0) return 'routes-format';
  }
  return null;
}

// Latency measurement pair (§4.2, §5). The token is opaque to the responder, which
// echoes it back unchanged, so only its type is constrained.
function validateTokenCarrier(f, want) {
  if (f.type !== want) return 'type';
  if (!('token' in f)) return 'missing-field';
  if (!isInt(f.token)) return 'token-format';
  return null;
}

// Tunneled BMX rekey (§4.2, security.md §6). Phases 1-3 carry the BMX bytes in
// `body`; phase 4 carries no BMX message and must omit it.
function validateRekey(f) {
  if (f.type !== 'rekey') return 'type';
  const m = midReason(f.mid);
  if (m) return m;
  if (!('phase' in f)) return 'missing-field';
  if (!isInt(f.phase) || f.phase < 1 || f.phase > 4) return 'phase-range';
  const hasBody = 'body' in f;
  if (f.phase === 4) return hasBody ? 'body-or-phase' : null;
  if (!hasBody) return 'body-or-phase';
  return base64Reason(f.body);
}

// Every named member must be present and Base64.
function requireBase64(f, keys) {
  for (const k of keys) {
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
  return checkChunking(f);
}

// Validates the splitting half of the data schema (protocol.md §6.1): the shape
// of `chunk`, its bounds, and the rule that exactly one of `payload` and `seg` is
// present.
//
// The exclusion is the load-bearing part. It is what stops a node that does not
// reassemble from handing a fragment to the application as though it were a whole
// message -- the silent corruption D11 described. A segment has no payload to
// deliver, so the mistake is unavailable rather than merely forbidden.
//
// Carrying neither stays 'missing-field' rather than becoming a splitting error:
// it is an absent field, the corpus has pinned that reason since 3.0.0, and
// renaming it here would have rewritten a vector rather than added one.
function checkChunking(f) {
  let n = 1;
  if ('chunk' in f) {
    const c = f.chunk;
    // An array passes typeof 'object' and is caught by the isInt checks below,
    // since c.i is undefined for one; mutation showed an explicit Array.isArray
    // test could not reject anything this does not already reject.
    if (c === null || typeof c !== 'object') return 'chunk-format';
    if (!isInt(c.i) || !isInt(c.n)) return 'chunk-format';
    n = c.n;
    if (n < 1 || n > MAX_CHUNKS) return 'chunk-range';
    if (c.i < 0 || c.i >= n) return 'chunk-range';
  }
  const hasPayload = 'payload' in f;
  const hasSeg = 'seg' in f;
  if (!hasPayload && !hasSeg) return 'missing-field';
  // Three clauses, none redundant. An explicit "both present" test was removed:
  // mutation showed it could not reject anything these two do not already reject,
  // since n is always 1 or more, so it read as coverage while asserting nothing.
  if (n === 1 && hasSeg) return 'payload-or-seg'; // a whole message carries its payload
  if (n > 1 && hasPayload) return 'payload-or-seg'; // a segment does not
  if (hasSeg && typeof f.seg !== 'string') return 'seg-format';
  return null;
}

function validateAck(f) {
  if (f.type !== 'ack') return 'type';
  return midReason(f.mid);
}

// A NAK is routed back toward the origin like data (to/from/ttl), naming the
// failing hop and a reason. The reason string is required but its value is not
// enum-checked, so a future reason value is not a wire break (protocol.md §8).
function validateNak(f) {
  if (f.type !== 'nak') return 'type';
  const m = midReason(f.mid);
  if (m) return m;
  if (typeof f.hop !== 'string' || f.hop === '') return 'missing-field';
  if (typeof f.reason !== 'string' || f.reason === '') return 'missing-field';
  if (typeof f.to !== 'string' || typeof f.from !== 'string') return 'missing-field';
  if (!isInt(f.ttl)) return 'missing-field';
  if (f.ttl < 1 || f.ttl > 255) return 'ttl-range';
  return null;
}

// A graceful session-close control — link-local, so only its type is required;
// an optional reason string is not validated further.
function validateBye(f) {
  if (f.type !== 'bye') return 'type';
  return null;
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

/**
 * Builds one segment of a split application message (protocol.md §6.1). A
 * segment carries `seg` and deliberately carries no `payload`: the two are
 * mutually exclusive, so a node that does not reassemble sees a data message with
 * no payload and rejects it rather than handing a fragment to the application as
 * though it were whole.
 */
export function dataSegment(mid, from, to, ttl, i, n, seg) {
  return { type: 'data', mid, from, to, ttl, chunk: { i, n }, seg };
}

// An acknowledgement routed back toward the origin (protocol.md §7): to is the
// origin, from is this node, ttl the hop limit.
export function ackTo(mid, from, to, ttl) {
  return { type: 'ack', mid, from, to, ttl };
}

// A negative acknowledgement naming the hop that failed and why, routed back
// toward the origin (protocol.md §7).
export function nak(mid, from, to, hop, reason, ttl) {
  return { type: 'nak', mid, hop, reason, from, to, ttl };
}

// A graceful session-close control. A reason is optional; omit it (undefined,
// null, or '') for a plain shutdown.
export function bye(reason) {
  const m = { type: 'bye' };
  if (reason !== undefined && reason !== null && reason !== '') m.reason = reason;
  return m;
}

export function echo(token) {
  return { type: 'echo', token };
}

// A liveness probe carrying the sender's send-time timestamp (ms), echoed back
// so the sender can measure RTT.
export function probe(token) {
  return { type: 'probe', token };
}

// A route advertisement: destination label -> path cost in ms.
export function disco(routes) {
  return { type: 'disco', routes };
}
