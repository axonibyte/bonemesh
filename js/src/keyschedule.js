// BMX key schedule (security.md §5): a Noise-style symmetric state carrying a
// transcript hash h and chaining key ck. Pinned constants match every other
// implementation (shared vector spec/corpus/transcripts/keyschedule.json).
import { sha256, hkdf, aeadSeal, aeadOpen } from './crypto.js';

export const PROTOCOL_NAME = 'BoneMesh_BMX_v3_X25519MLKEM768_ChaChaPoly_SHA256';

const EMPTY = Buffer.alloc(0);

export class KeySchedule {
  constructor() {
    this.h = sha256(Buffer.from(PROTOCOL_NAME, 'utf8'));
    this.ck = Buffer.from(this.h);
    this.key = null;
    this.nonce = 0n;
  }

  // h = SHA-256(h || data)
  mixHash(data) {
    this.h = sha256(Buffer.concat([this.h, data]));
  }

  // Derive a fresh key and chaining key, resetting the nonce.
  mixKey(ikm) {
    const okm = hkdf(this.ck, ikm ?? EMPTY, EMPTY, 64);
    this.ck = okm.subarray(0, 32);
    this.key = okm.subarray(32, 64);
    this.nonce = 0n;
  }

  // Seal plaintext with h as AAD, then absorb the ciphertext.
  encryptAndHash(plaintext) {
    const ct = aeadSeal(this.key, this.#nonce12(), this.h, plaintext);
    this.nonce++;
    this.mixHash(ct);
    return ct;
  }

  // Open a ciphertext (AAD is the current h), then absorb it. Returns null on
  // authentication failure.
  decryptAndHash(ciphertext) {
    const ad = this.h;
    const pt = aeadOpen(this.key, this.#nonce12(), ad, ciphertext);
    if (pt === null) return null;
    this.nonce++;
    this.mixHash(ciphertext);
    return pt;
  }

  // Derive the two directional transport keys: [i2r, r2i].
  split() {
    const okm = hkdf(this.ck, EMPTY, EMPTY, 64);
    return [okm.subarray(0, 32), okm.subarray(32, 64)];
  }

  #nonce12() {
    const n = Buffer.alloc(12);
    n.writeBigUInt64LE(this.nonce, 4);
    return n;
  }
}
