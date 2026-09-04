/*
 * Copyright (c) 2026 Axonibyte Innovations, LLC. All rights reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.axonibyte.bonemesh.v3.handshake;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import org.json.JSONObject;

import com.axonibyte.bonemesh.v3.cert.Certificate;
import com.axonibyte.bonemesh.v3.crypto.Aead;
import com.axonibyte.bonemesh.v3.crypto.Dh;
import com.axonibyte.bonemesh.v3.crypto.Kem;
import com.axonibyte.bonemesh.v3.crypto.Signer;

/**
 * The BMX handshake (security.md &sect;4): a three-message, mutually
 * authenticated, forward-secret exchange. Forward secrecy comes from the hybrid
 * of an ephemeral X25519 agreement and an ephemeral ML-KEM-768 encapsulation
 * (both mixed via {@link SymmetricState}); authentication comes from each side
 * presenting a root-signed {@link Certificate} and an ML-DSA signature over the
 * live transcript, so a replayed certificate proves nothing.
 *
 * <p>This class drives the state machine over byte messages (JSON lines); the
 * transport layer supplies the actual sockets. It is single-use: one instance
 * runs one handshake.</p>
 *
 * @author Caleb L. Power
 */
public final class Handshake {

  private static final int VERSION = 3;
  private static final Base64.Encoder B64ENC = Base64.getEncoder();
  private static final Base64.Decoder B64DEC = Base64.getDecoder();

  private final boolean initiator;
  private final String mesh;
  private final byte[] rootPublicKey;
  private final long now;
  private final Certificate ownCertificate;
  private final Signer ownIdentity;
  private final SecureRandom rng;

  private final SymmetricState state = new SymmetricState();

  // Initiator-held ephemerals, needed across messages 1 and 2.
  private Dh ephemeralDh;
  private Kem ephemeralKem;

  private Session session;
  private Certificate peerCertificate;

  private Handshake(boolean initiator, String mesh, byte[] rootPublicKey, long now,
      Certificate ownCertificate, Signer ownIdentity, SecureRandom rng) {
    this.initiator = initiator;
    this.mesh = mesh;
    this.rootPublicKey = rootPublicKey;
    this.now = now;
    this.ownCertificate = ownCertificate;
    this.ownIdentity = ownIdentity;
    this.rng = rng;
    state.mixHash(mesh.getBytes(StandardCharsets.UTF_8)); // prologue binds the mesh
  }

  /**
   * Creates the initiating side of a handshake.
   *
   * @param mesh the mesh identifier
   * @param rootPublicKey the pinned raw ML-DSA-87 root public key
   * @param now the current time (Unix seconds), for certificate validity
   * @param ownCertificate this node's membership certificate
   * @param ownIdentity this node's ML-DSA-65 identity (with private key)
   * @param rng the randomness source
   * @return the initiator handshake
   */
  public static Handshake initiator(String mesh, byte[] rootPublicKey, long now,
      Certificate ownCertificate, Signer ownIdentity, SecureRandom rng) {
    return new Handshake(true, mesh, rootPublicKey, now, ownCertificate, ownIdentity, rng);
  }

  /**
   * Creates the responding side of a handshake.
   *
   * @param mesh the mesh identifier
   * @param rootPublicKey the pinned raw ML-DSA-87 root public key
   * @param now the current time (Unix seconds)
   * @param ownCertificate this node's membership certificate
   * @param ownIdentity this node's ML-DSA-65 identity (with private key)
   * @param rng the randomness source
   * @return the responder handshake
   */
  public static Handshake responder(String mesh, byte[] rootPublicKey, long now,
      Certificate ownCertificate, Signer ownIdentity, SecureRandom rng) {
    return new Handshake(false, mesh, rootPublicKey, now, ownCertificate, ownIdentity, rng);
  }

  /**
   * Initiator: produces message 1 (fresh ephemerals, in the clear).
   *
   * @return the bmx1 JSON line bytes
   */
  public byte[] writeMessage1() {
    require(initiator, "only the initiator writes message 1");
    ephemeralDh = Dh.generate(rng);
    ephemeralKem = Kem.generate(rng);
    byte[] n = new byte[32];
    rng.nextBytes(n);

    state.mixHash(ephemeralDh.publicKey());
    state.mixHash(ephemeralKem.encapsulationKey());
    state.mixHash(n);

    JSONObject m = new JSONObject()
        .put("t", "bmx1").put("v", VERSION).put("mesh", mesh)
        .put("e", B64ENC.encodeToString(ephemeralDh.publicKey()))
        .put("k", B64ENC.encodeToString(ephemeralKem.encapsulationKey()))
        .put("n", B64ENC.encodeToString(n));
    return line(m);
  }

  /**
   * Responder: consumes message 1 and produces message 2 (its ephemeral, the
   * KEM ciphertext, and its encrypted certificate + transcript signature).
   *
   * @param message1 the bmx1 bytes
   * @return the bmx2 JSON line bytes
   * @throws HandshakeException if message 1 is malformed or from another mesh
   */
  public byte[] readMessage1WriteMessage2(byte[] message1) throws HandshakeException {
    require(!initiator, "only the responder reads message 1");
    JSONObject m = parse(message1, "bmx1");
    if(m.getInt("v") != VERSION) throw new HandshakeException("unsupported version " + m.getInt("v"));
    if(!mesh.equals(m.getString("mesh"))) throw new HandshakeException("mesh mismatch");

    byte[] eiPub = B64DEC.decode(m.getString("e"));
    byte[] kiEk = B64DEC.decode(m.getString("k"));
    byte[] n = B64DEC.decode(m.getString("n"));
    state.mixHash(eiPub);
    state.mixHash(kiEk);
    state.mixHash(n);

    Dh er = Dh.generate(rng);
    state.mixHash(er.publicKey());
    state.mixKey(er.agree(eiPub));

    Kem.Encapsulation enc = Kem.encapsulateTo(kiEk, rng);
    state.mixHash(enc.ciphertext());
    state.mixKey(enc.secret());

    byte[] auth = sealIdentity();

    JSONObject out = new JSONObject()
        .put("t", "bmx2")
        .put("e", B64ENC.encodeToString(er.publicKey()))
        .put("ct", B64ENC.encodeToString(enc.ciphertext()))
        .put("auth", B64ENC.encodeToString(auth));
    return line(out);
  }

  /**
   * Initiator: consumes message 2 (verifying the responder) and produces
   * message 3 (its own encrypted certificate + transcript signature),
   * completing the initiator side.
   *
   * @param message2 the bmx2 bytes
   * @return the bmx3 JSON line bytes
   * @throws HandshakeException if verification fails
   */
  public byte[] readMessage2WriteMessage3(byte[] message2) throws HandshakeException {
    require(initiator, "only the initiator reads message 2");
    JSONObject m = parse(message2, "bmx2");

    byte[] erPub = B64DEC.decode(m.getString("e"));
    byte[] ct = B64DEC.decode(m.getString("ct"));
    byte[] auth = B64DEC.decode(m.getString("auth"));

    state.mixHash(erPub);
    state.mixKey(ephemeralDh.agree(erPub));
    state.mixHash(ct);
    state.mixKey(ephemeralKem.decapsulate(ct));

    openAndVerifyIdentity(auth);

    byte[] myAuth = sealIdentity();
    JSONObject out = new JSONObject().put("t", "bmx3").put("auth", B64ENC.encodeToString(myAuth));

    byte[][] tk = state.split();
    // Initiator sends on i2r (tk[0]), receives on r2i (tk[1]).
    session = new Session(tk[0], tk[1], peerCertificate);
    return line(out);
  }

  /**
   * Responder: consumes message 3, verifying the initiator and completing the
   * handshake.
   *
   * @param message3 the bmx3 bytes
   * @throws HandshakeException if verification fails
   */
  public void readMessage3(byte[] message3) throws HandshakeException {
    require(!initiator, "only the responder reads message 3");
    JSONObject m = parse(message3, "bmx3");
    openAndVerifyIdentity(B64DEC.decode(m.getString("auth")));

    byte[][] tk = state.split();
    // Responder sends on r2i (tk[1]), receives on i2r (tk[0]).
    session = new Session(tk[1], tk[0], peerCertificate);
  }

  /** @return <code>true</code> once this side of the handshake has completed */
  public boolean isComplete() {
    return session != null;
  }

  /**
   * @return the completed session
   * @throws IllegalStateException if the handshake has not completed
   */
  public Session session() {
    if(session == null) throw new IllegalStateException("handshake not complete");
    return session;
  }

  // Signs the current transcript, packages {cert, sig}, and encrypts it into
  // the transcript.
  private byte[] sealIdentity() {
    byte[] sig = ownIdentity.sign(state.transcriptHash());
    JSONObject payload = new JSONObject()
        .put("cert", ownCertificate.toJSON())
        .put("sig", B64ENC.encodeToString(sig));
    return state.encryptAndHash(payload.toString().getBytes(StandardCharsets.UTF_8));
  }

  // Decrypts the peer's identity, verifies its certificate against the pinned
  // root, and verifies its transcript signature (proving live key possession).
  private void openAndVerifyIdentity(byte[] auth) throws HandshakeException {
    byte[] transcriptAtSigning = state.transcriptHash(); // h the peer signed, before absorbing auth
    byte[] plaintext;
    try {
      plaintext = state.decryptAndHash(auth);
    } catch(Aead.AeadException e) {
      throw new HandshakeException("handshake authentication failed: " + e.getMessage());
    }
    JSONObject payload = new JSONObject(new String(plaintext, StandardCharsets.UTF_8));
    Certificate peerCert;
    try {
      peerCert = Certificate.fromJSON(payload.getJSONObject("cert"));
      peerCert.verify(rootPublicKey, mesh, now);
    } catch(Certificate.CertificateException e) {
      throw new HandshakeException("peer certificate invalid: " + e.getMessage());
    }
    byte[] sig = B64DEC.decode(payload.getString("sig"));
    boolean ok = Signer.verifier(Signer.Level.DSA65, peerCert.identityKey())
        .verify(transcriptAtSigning, sig);
    if(!ok) throw new HandshakeException("peer transcript signature does not verify");
    this.peerCertificate = peerCert;
  }

  private JSONObject parse(byte[] message, String expectedType) throws HandshakeException {
    JSONObject m = new JSONObject(new String(message, StandardCharsets.UTF_8).trim());
    if(!expectedType.equals(m.optString("t")))
      throw new HandshakeException("expected " + expectedType + ", got " + m.optString("t"));
    return m;
  }

  private static byte[] line(JSONObject o) {
    return (o.toString() + "\n").getBytes(StandardCharsets.UTF_8);
  }

  private static void require(boolean condition, String message) {
    if(!condition) throw new IllegalStateException(message);
  }

  /** Thrown when a handshake message is malformed or authentication fails. */
  public static final class HandshakeException extends Exception {
    HandshakeException(String message) {
      super(message);
    }
  }
}
