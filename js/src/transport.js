// Encrypted transport channel over a completed handshake (protocol.md §4): each
// frame is a sequence-numbered AEAD carrier {"seq":n,"ct":...} whose plaintext
// is the inner JSON message. The per-direction sequence is the
// ChaCha20-Poly1305 nonce; reordered or replayed frames are rejected. Matches
// the shared transport-frame vector.
import { aeadSeal, aeadOpen } from './crypto.js';

export class Transport {
  // session is a completed handshake session { sendKey, receiveKey }.
  constructor(session) {
    this.sendKey = session.sendKey;
    this.receiveKey = session.receiveKey;
    this.sendSeq = 0n;
    this.receiveSeq = 0n;
  }

  // Seal an inner message into a { seq, ct } carrier object.
  seal(inner) {
    const seq = this.sendSeq;
    const pt = Buffer.from(JSON.stringify(inner), 'utf8');
    const ct = sealCiphertext(this.sendKey, seq, pt);
    this.sendSeq++;
    return { seq: Number(seq), ct: ct.toString('base64') };
  }

  // Per-direction frame counters, so a node can decide when a rekey is due (F5).
  sendSeq_() { return this.sendSeq; }
  receiveSeq_() { return this.receiveSeq; }

  // Install a new outbound key and reset the send counter to 0, at the rekey
  // boundary immediately after sealing the last old-key frame (F5).
  swapSend(key) {
    this.sendKey = key;
    this.sendSeq = 0n;
  }

  // Install a new inbound key and reset the receive counter, immediately after
  // opening the last old-key frame in this direction.
  swapReceive(key) {
    this.receiveKey = key;
    this.receiveSeq = 0n;
  }

  // Open a carrier, enforcing in-order delivery. Returns the inner object, or
  // throws on gap/replay or authentication failure.
  open(carrier) {
    const seq = BigInt(carrier.seq);
    if (seq !== this.receiveSeq) throw new Error('out-of-order frame');
    const ct = Buffer.from(carrier.ct, 'base64');
    const pt = openCiphertext(this.receiveKey, seq, ct);
    if (pt === null) throw new Error('frame authentication failed');
    this.receiveSeq++;
    return JSON.parse(pt.toString('utf8'));
  }
}

// The frame body alone, addressed by sequence number rather than by session
// state. This is the form the shared transport-frame vector
// (spec/corpus/transcripts/transport-frame.json) is stated in, and the form
// bonemesh-inspect needs; Transport.seal/open are the stateful wrappers, so the
// nonce is constructed in exactly one place.
export function sealCiphertext(key, seq, plaintext) {
  return aeadSeal(key, nonce(BigInt(seq)), null, plaintext);
}

// Returns the plaintext, or null if authentication fails.
export function openCiphertext(key, seq, ct) {
  return aeadOpen(key, nonce(BigInt(seq)), null, ct);
}

function nonce(seq) {
  const n = Buffer.alloc(12);
  n.writeBigUInt64LE(seq, 4);
  return n;
}
