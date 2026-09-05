// BoneMesh v3 cryptographic primitives (security.md §1): SHA-256, HKDF-SHA-256,
// ChaCha20-Poly1305, X25519, ML-KEM-768, and ML-DSA-65/87. Everything is Node's
// built-in crypto (OpenSSL 3.5): no external dependency, like the Elixir port on
// OTP. Public keys, ciphertexts, secrets, and signatures are the raw FIPS/RFC
// encodings, matching the Java, Elixir, Rust, and Go implementations.
//
// Only the node identity's ML-DSA private key is ever serialized (as opaque
// PKCS#8 DER, which never crosses a node boundary). Ephemeral X25519 and ML-KEM
// keys live in memory as KeyObjects for the duration of a handshake.
import crypto from 'node:crypto';

const b64u = (b) => Buffer.from(b).toString('base64url');
const fromB64u = (s) => Buffer.from(s, 'base64url');

// --- hashing / KDF -------------------------------------------------------

export function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

// Full extract-then-expand HKDF-SHA-256 (RFC 5869).
export function hkdf(salt, ikm, info, length) {
  return Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info ?? Buffer.alloc(0), length));
}

// --- AEAD ----------------------------------------------------------------

// ChaCha20-Poly1305 with the 16-byte tag appended to the ciphertext.
export function aeadSeal(key, nonce, aad, plaintext) {
  const cipher = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  if (aad && aad.length) cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([ct, cipher.getAuthTag()]);
}

// Returns the plaintext Buffer, or null on tag failure.
export function aeadOpen(key, nonce, aad, ct) {
  if (ct.length < 16) return null;
  const body = ct.subarray(0, ct.length - 16);
  const tag = ct.subarray(ct.length - 16);
  try {
    const d = crypto.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
    if (aad && aad.length) d.setAAD(aad);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(body), d.final()]);
  } catch {
    return null;
  }
}

// --- X25519 --------------------------------------------------------------

// Returns { pub: Buffer(32), priv: KeyObject }. The private key stays in memory.
export function x25519Generate() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  return { pub: fromB64u(publicKey.export({ format: 'jwk' }).x), priv: privateKey };
}

export function x25519Agree(privKeyObject, peerPubRaw) {
  const publicKey = crypto.createPublicKey({
    key: { kty: 'OKP', crv: 'X25519', x: b64u(peerPubRaw) },
    format: 'jwk',
  });
  return crypto.diffieHellman({ privateKey: privKeyObject, publicKey });
}

// --- ML-KEM-768 ----------------------------------------------------------

// Returns { ek: Buffer(1184), dk: KeyObject }. The decapsulation key stays in
// memory (its seed representation never crosses a node).
export function mlkem768Keypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ml-kem-768');
  return { ek: fromB64u(publicKey.export({ format: 'jwk' }).pub), dk: privateKey };
}

// Encapsulates to a raw encapsulation key, returning { ss, ct }.
export function mlkem768Encapsulate(ekRaw) {
  const publicKey = crypto.createPublicKey({
    key: { kty: 'AKP', alg: 'ML-KEM-768', pub: b64u(ekRaw) },
    format: 'jwk',
  });
  const { sharedKey, ciphertext } = crypto.encapsulate(publicKey);
  return { ss: sharedKey, ct: ciphertext };
}

// Recovers the shared secret, or null on failure.
export function mlkem768Decapsulate(dkKeyObject, ct) {
  try {
    return crypto.decapsulate(dkKeyObject, ct);
  } catch {
    return null;
  }
}

// --- ML-DSA --------------------------------------------------------------

// Returns { pub: Buffer(1952 raw), priv: Buffer(PKCS#8 DER) } for a node
// identity. The DER private key round-trips through Node natively and is opaque
// to every other implementation.
export function mldsa65Generate() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ml-dsa-65');
  return {
    pub: fromB64u(publicKey.export({ format: 'jwk' }).pub),
    priv: privateKey.export({ type: 'pkcs8', format: 'der' }),
  };
}

export function mldsa65Sign(privDer, message) {
  const privateKey = crypto.createPrivateKey({ key: privDer, format: 'der', type: 'pkcs8' });
  return crypto.sign(null, message, privateKey);
}

export function mldsa65Verify(pubRaw, message, signature) {
  return verifyAKP('ML-DSA-65', pubRaw, message, signature);
}

// ML-DSA-87 verification — the mesh root.
export function mldsa87Verify(pubRaw, message, signature) {
  return verifyAKP('ML-DSA-87', pubRaw, message, signature);
}

function verifyAKP(alg, pubRaw, message, signature) {
  try {
    const publicKey = crypto.createPublicKey({
      key: { kty: 'AKP', alg, pub: b64u(pubRaw) },
      format: 'jwk',
    });
    return crypto.verify(null, message, publicKey, signature);
  } catch {
    return false;
  }
}
