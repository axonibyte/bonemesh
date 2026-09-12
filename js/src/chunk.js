// Splitting and reassembly of oversized application payloads (protocol.md §6.1).
//
// A payload too large for one transport frame is serialized, its UTF-8 bytes cut
// into segments of at most MAX_SEGMENT_BYTES on character boundaries, and each
// segment sent as a data message sharing one message id, carrying chunk {i, n}
// and a top-level `seg` string and NO `payload`. A payload that fits travels
// whole, with `payload` and no `seg`.
//
// Segments are text, not Base64: §0's Base64 rule covers binary fields, a slice
// of JSON text is already UTF-8, and a JSON string carries it directly, so a
// split message stays readable through the key-log inspector (decisions #3, #5,
// #25). Cutting on a byte budget rather than a character count is what keeps the
// split identical across the seven implementations -- and in this port it is also
// what makes it correct at all, since a JavaScript string is UTF-16 and its
// .length is not its byte count. Everything here goes through Buffer for that
// reason.

import { dataSegment, data } from './message.js';

/** Maximum payload bytes carried by one segment (protocol.md §0). */
export const MAX_SEGMENT_BYTES = 24000;
/** Maximum segments one application message may be split into (§0). */
export const MAX_CHUNKS = 1024;
/** Maximum segment bytes buffered at once, across every in-flight message (§0). */
export const MAX_REASSEMBLY_BUFFER = 16777216;
/** Maximum messages that may be mid-reassembly at once (§0). */
export const MAX_CONCURRENT_REASSEMBLIES = 256;
/** Milliseconds a partially-filled message may sit before being discarded (§0). */
export const REASSEMBLY_TIMEOUT_MILLIS = 30000;

// Walks a proposed cut back to the nearest character boundary at or before it, so
// a segment never ends mid-character and is always itself valid UTF-8.
function charBoundary(buf, start, end) {
  if (end >= buf.length) return end; // the tail is always a boundary
  let e = end;
  while (e > start && (buf[e] & 0xc0) === 0x80) e--; // 10xxxxxx is a continuation byte
  // A UTF-8 character is at most 4 bytes and a segment is 24000, so e cannot reach
  // start from well-formed input; falling back keeps a malformed serializer from
  // producing a zero-length segment and looping forever.
  return e > start ? e : end;
}

/**
 * Splits a payload into one whole data message or a series of segments.
 * Throws when no conforming destination would reassemble it, so the caller is
 * told locally rather than the mesh carrying a message that cannot arrive
 * (§6.1, Bounds).
 */
export function split(mid, from, to, ttl, payload) {
  const src = Buffer.from(JSON.stringify(payload), 'utf8');
  if (src.length <= MAX_SEGMENT_BYTES) return [data(mid, from, to, ttl, payload)];
  if (src.length > MAX_REASSEMBLY_BUFFER)
    throw new Error(
      `payload of ${src.length} bytes exceeds the reassembly buffer maximum of ${MAX_REASSEMBLY_BUFFER}`,
    );

  const segs = [];
  for (let pos = 0; pos < src.length; ) {
    const end = charBoundary(src, pos, Math.min(pos + MAX_SEGMENT_BYTES, src.length));
    segs.push(src.toString('utf8', pos, end));
    pos = end;
  }
  if (segs.length > MAX_CHUNKS)
    throw new Error(`payload needs ${segs.length} segments, over the maximum of ${MAX_CHUNKS}`);

  return segs.map((seg, i) => dataSegment(mid, from, to, ttl, i, segs.length, seg));
}

// An integer index, and only an integer. Number.isInteger already rejects a
// fractional value and a non-number; it cannot reject the JSON text "3.0",
// because JSON.parse produces the same value for 3.0 and 3. No conforming sender
// emits that form, so the leniency is unobservable between conforming peers --
// recorded in §6.1 rather than worked around here.
function chunkInt(v) {
  return typeof v === 'number' && Number.isInteger(v) ? v : null;
}

/**
 * Rebuilds split payloads at the destination, the counterpart to split().
 *
 * Every §0 bound is enforced BEFORE any allocation keyed on a number the peer
 * chose. That ordering is the point: the Java reference sized its buffer on the
 * peer's n and validated afterwards, so one frame claiming two billion segments
 * exhausted the heap -- defect D7 reintroduced by the feature meant to fix it.
 *
 * Three bounds, none redundant. The byte budget caps one large message; the
 * in-flight count caps a flood of distinct ids each carrying an empty segment,
 * which costs nothing against a byte budget and still costs memory; the timeout
 * stops an abandoned message pinning memory for the session's life.
 */
export class Reassembler {
  #partials = new Map(); // insertion-ordered, so the sweep walks oldest-first
  #buffered = 0;

  /**
   * Feeds one inbound data message. Returns the payload when a message
   * completes, else undefined. nowMillis is passed in rather than read so the
   * timeout is testable without sleeping.
   */
  offer(msg, nowMillis) {
    this.#sweep(nowMillis);

    const hasChunk = msg !== null && typeof msg === 'object' && 'chunk' in msg;
    const chunk = hasChunk && msg.chunk !== null && typeof msg.chunk === 'object' ? msg.chunk : null;
    if (hasChunk && chunk === null) return undefined; // chunk is not an object
    const n = chunk === null ? 1 : chunkInt(chunk.n);
    if (hasChunk && n === null) return undefined;

    if (!hasChunk || n === 1) {
      // A whole message carries payload and no seg. One claiming n === 1 while
      // carrying seg instead is malformed, not a one-segment split -- and so is
      // one carrying both.
      if ('seg' in msg) return undefined;
      return 'payload' in msg ? msg.payload : undefined;
    }

    // Bounds first, allocation second.
    const i = chunkInt(chunk.i);
    if (i === null || n < 1 || n > MAX_CHUNKS || i < 0 || i >= n) return undefined;
    if (typeof msg.seg !== 'string') return undefined; // a segment without its slice
    if (typeof msg.mid !== 'string') return undefined;

    let p = this.#partials.get(msg.mid);
    if (p === undefined) {
      if (this.#partials.size >= MAX_CONCURRENT_REASSEMBLIES) return undefined;
      p = { segments: new Array(n).fill(null), received: 0, bytes: 0, started: nowMillis };
      this.#partials.set(msg.mid, p);
    } else if (p.segments.length !== n) {
      this.#discard(msg.mid, p); // the peer changed n mid-message
      return undefined;
    }

    if (p.segments[i] === null) {
      const size = Buffer.byteLength(msg.seg, 'utf8');
      if (this.#buffered + size > MAX_REASSEMBLY_BUFFER) {
        this.#discard(msg.mid, p);
        return undefined;
      }
      p.segments[i] = msg.seg;
      p.bytes += size;
      p.received++;
      this.#buffered += size;
    }
    if (p.received !== n) return undefined;

    this.#discard(msg.mid, p);
    try {
      return JSON.parse(p.segments.join(''));
    } catch {
      return undefined; // the segments did not rebuild valid JSON
    }
  }

  /**
   * Messages currently mid-reassembly. Exposed for the tests that assert the
   * bounds release memory rather than merely refusing to add to it -- a
   * reassembler that rejects a segment but keeps its partial forever is still a
   * leak, and the refusal alone cannot show that.
   */
  inFlight() {
    return this.#partials.size;
  }

  /** Segment bytes held across every in-flight message. */
  buffered() {
    return this.#buffered;
  }

  #discard(mid, p) {
    this.#partials.delete(mid);
    this.#buffered -= p.bytes;
  }

  #sweep(nowMillis) {
    for (const [mid, p] of this.#partials) {
      if (nowMillis - p.started < REASSEMBLY_TIMEOUT_MILLIS) break; // insertion-ordered
      this.#partials.delete(mid);
      this.#buffered -= p.bytes;
    }
  }
}
