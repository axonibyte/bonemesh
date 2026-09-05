// BoneMesh v3 membership certificate (security.md §3): a mesh-root-signed
// binding of a label to a node's ML-DSA-65 identity key. Represented as a plain
// object (the JSON form); its signed pre-image is the canon canonicalization of
// every field except "sig". Base64 fields are the standard alphabet.
import { canonicalize } from './canon.js';
import { mldsa87Verify } from './crypto.js';

// Build an unsigned certificate. identityKey is the raw ML-DSA-65 public key.
export function build(mesh, label, identityKey, notBefore, notAfter) {
  return {
    v: 3,
    mesh,
    label,
    idk: Buffer.from(identityKey).toString('base64'),
    nbf: notBefore,
    exp: notAfter,
  };
}

// Verify a certificate against the pinned root public key, mesh, and time.
// Returns null if valid, else a reason string.
export function verify(cert, rootPublic, expectedMesh, now) {
  if (cert.mesh !== expectedMesh) return 'mesh mismatch';
  if (typeof cert.nbf !== 'number' || now < cert.nbf) return 'certificate not yet valid';
  if (typeof cert.exp !== 'number' || now > cert.exp) return 'certificate expired';
  if (typeof cert.sig !== 'string') return 'certificate is unsigned';
  let sig;
  try {
    sig = Buffer.from(cert.sig, 'base64');
  } catch {
    return 'signature is not base64';
  }
  let preImage;
  try {
    preImage = canonicalize(cert);
  } catch (e) {
    return `canon: ${e.message}`;
  }
  if (!mldsa87Verify(rootPublic, Buffer.from(preImage, 'utf8'), sig)) {
    return 'root signature does not verify';
  }
  return null;
}

// The node's raw ML-DSA-65 public key.
export function identityKey(cert) {
  return Buffer.from(cert.idk, 'base64');
}
