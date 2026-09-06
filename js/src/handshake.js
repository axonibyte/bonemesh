// BMX handshake (security.md §4): a three-message, mutually authenticated,
// forward-secret exchange. Hybrid X25519 + ML-KEM-768 forward secrecy through
// the key schedule; authentication by a root-signed certificate plus an ML-DSA
// signature over the live transcript. Field-for-field identical to the Java,
// Elixir, Rust, and Go implementations.
//
// The write* methods return an encoded frame Buffer ready for the wire; the
// read* methods take the peer's already-decoded frame object.
import crypto from 'node:crypto';
import { KeySchedule } from './keyschedule.js';
import { encode } from './frame.js';
import * as c from './crypto.js';
import * as cert from './cert.js';

const b64 = (b) => Buffer.from(b).toString('base64');
const unb64 = (s) => Buffer.from(s, 'base64');

export class Handshake {
  constructor(mesh, rootPublic, now, certObj, idPrivate) {
    this.mesh = mesh;
    this.rootPublic = rootPublic;
    this.now = now;
    this.cert = certObj;
    this.idPrivate = idPrivate;
    this.ks = new KeySchedule();
    this.ks.mixHash(Buffer.from(mesh, 'utf8'));
    this.session = null;
  }

  static initiator(mesh, rootPublic, now, certObj, idPrivate) {
    return new Handshake(mesh, rootPublic, now, certObj, idPrivate);
  }

  static responder(mesh, rootPublic, now, certObj, idPrivate) {
    return new Handshake(mesh, rootPublic, now, certObj, idPrivate);
  }

  // Message 1 (initiator).
  writeMessage1() {
    const dh = c.x25519Generate();
    const kem = c.mlkem768Keypair();
    const n = crypto.randomBytes(32);
    this.ephDHPub = dh.pub;
    this.ephDHPriv = dh.priv;
    this.ephKEMek = kem.ek;
    this.ephKEMdk = kem.dk;
    this.ks.mixHash(dh.pub);
    this.ks.mixHash(kem.ek);
    this.ks.mixHash(n);
    return encode({ t: 'bmx1', v: 3, mesh: this.mesh, e: b64(dh.pub), k: b64(kem.ek), n: b64(n) });
  }

  // Message 2 (responder): consume msg1, produce msg2.
  readMessage1WriteMessage2(m) {
    if (m.t !== 'bmx1') throw new Error('expected bmx1');
    if (m.v !== 3) throw new Error('unsupported version');
    if (m.mesh !== this.mesh) throw new Error('mesh mismatch');
    this.ks.mixHash(unb64(m.e));
    this.ks.mixHash(unb64(m.k));
    this.ks.mixHash(unb64(m.n));

    const er = c.x25519Generate();
    this.ks.mixHash(er.pub);
    this.ks.mixKey(c.x25519Agree(er.priv, unb64(m.e)));

    const { ss, ct } = c.mlkem768Encapsulate(unb64(m.k));
    this.ks.mixHash(ct);
    this.ks.mixKey(ss);

    const auth = this.#sealIdentity();
    return encode({ t: 'bmx2', e: b64(er.pub), ct: b64(ct), auth: b64(auth) });
  }

  // Message 3 (initiator): verify responder, produce msg3.
  readMessage2WriteMessage3(m) {
    const erPub = unb64(m.e);
    const ct = unb64(m.ct);
    const auth = unb64(m.auth);

    this.ks.mixHash(erPub);
    this.ks.mixKey(c.x25519Agree(this.ephDHPriv, erPub));
    this.ks.mixHash(ct);
    const ssKem = c.mlkem768Decapsulate(this.ephKEMdk, ct);
    if (ssKem === null) throw new Error('decapsulation failed');
    this.ks.mixKey(ssKem);

    const peerCert = this.#openIdentity(auth);
    const authI = this.#sealIdentity();
    const out = encode({ t: 'bmx3', auth: b64(authI) });
    const [i2r, r2i] = this.ks.split();
    this.session = { sendKey: i2r, receiveKey: r2i, peerCert, h: Buffer.from(this.ks.h) };
    return out;
  }

  // Message 3 (responder): verify initiator, completing the handshake.
  readMessage3(m) {
    const peerCert = this.#openIdentity(unb64(m.auth));
    const [i2r, r2i] = this.ks.split();
    this.session = { sendKey: r2i, receiveKey: i2r, peerCert, h: Buffer.from(this.ks.h) };
  }

  #sealIdentity() {
    const sig = c.mldsa65Sign(this.idPrivate, this.ks.h);
    const payload = Buffer.from(JSON.stringify({ cert: this.cert, sig: b64(sig) }), 'utf8');
    return this.ks.encryptAndHash(payload);
  }

  #openIdentity(auth) {
    const hPre = Buffer.from(this.ks.h);
    const pt = this.ks.decryptAndHash(auth);
    if (pt === null) throw new Error('handshake authentication failed');
    let payload;
    try {
      payload = JSON.parse(pt.toString('utf8'));
    } catch {
      throw new Error('bad auth payload');
    }
    const peerCert = payload.cert;
    const reason = cert.verify(peerCert, this.rootPublic, this.mesh, this.now);
    if (reason) throw new Error(`peer certificate invalid: ${reason}`);
    const idk = cert.identityKey(peerCert);
    if (!c.mldsa65Verify(idk, hPre, unb64(payload.sig))) {
      throw new Error('peer transcript signature does not verify');
    }
    return peerCert;
  }
}
