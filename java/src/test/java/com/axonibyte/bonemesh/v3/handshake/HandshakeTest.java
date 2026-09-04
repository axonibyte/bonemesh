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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.axonibyte.bonemesh.v3.cert.Certificate;
import com.axonibyte.bonemesh.v3.crypto.Signer;

/**
 * In-memory BMX handshake tests: a full mutually-authenticated exchange between
 * two nodes of one mesh, and the rejections that keep an outsider or a
 * tamperer out. Cross-language agreement on the derived keys is frozen
 * separately by the handshake key-agreement vector.
 */
public class HandshakeTest {

  private static final SecureRandom RNG = new SecureRandom();
  private static final String MESH = "acme-prod";
  private static final long NOW = 1_788_600_000L;

  private Signer root;
  private byte[] rootPub;
  private Signer alphaId;
  private Signer betaId;
  private Certificate alphaCert;
  private Certificate betaCert;

  @BeforeEach void setUp() {
    root = Signer.generate(Signer.Level.DSA87, RNG);
    rootPub = root.publicKey();
    alphaId = Signer.generate(Signer.Level.DSA65, RNG);
    betaId = Signer.generate(Signer.Level.DSA65, RNG);
    alphaCert = issue("alpha", alphaId, NOW - 100, NOW + 100);
    betaCert = issue("beta", betaId, NOW - 100, NOW + 100);
  }

  private Certificate issue(String label, Signer id, long nbf, long exp) {
    return new Certificate(MESH, label, id.publicKey(), nbf, exp).sign(root);
  }

  private Handshake initiator(Certificate cert, Signer id) {
    return Handshake.initiator(MESH, rootPub, NOW, cert, id, RNG);
  }

  private Handshake responder(String mesh, byte[] pinnedRoot, Certificate cert, Signer id) {
    return Handshake.responder(mesh, pinnedRoot, NOW, cert, id, RNG);
  }

  @Test void fullHandshakeMutuallyAuthenticatesAndAgreesOnKeys() throws Exception {
    Handshake a = initiator(alphaCert, alphaId);
    Handshake b = responder(MESH, rootPub, betaCert, betaId);

    byte[] m1 = a.writeMessage1();
    byte[] m2 = b.readMessage1WriteMessage2(m1);
    byte[] m3 = a.readMessage2WriteMessage3(m2);
    b.readMessage3(m3);

    assertTrue(a.isComplete());
    assertTrue(b.isComplete());

    // The two directions line up: what one sends with, the other receives with.
    assertArrayEquals(a.session().sendKey(), b.session().receiveKey());
    assertArrayEquals(a.session().receiveKey(), b.session().sendKey());
    // And the send/receive keys genuinely differ (no shared key/nonce space).
    assertFalse(java.util.Arrays.equals(a.session().sendKey(), a.session().receiveKey()));

    // Each learned the other's authenticated identity.
    assertEquals("beta", a.session().peerCertificate().label());
    assertEquals("alpha", b.session().peerCertificate().label());
  }

  @Test void responderRejectsForeignMesh() throws Exception {
    Handshake a = initiator(alphaCert, alphaId);
    Handshake b = responder("other-mesh", rootPub, betaCert, betaId);
    byte[] m1 = a.writeMessage1();
    assertThrows(Handshake.HandshakeException.class, () -> b.readMessage1WriteMessage2(m1));
  }

  @Test void initiatorRejectsResponderSignedByAnotherRoot() throws Exception {
    // Beta's cert is signed by a different root than alpha pins.
    Signer otherRoot = Signer.generate(Signer.Level.DSA87, RNG);
    Certificate betaForeign =
        new Certificate(MESH, "beta", betaId.publicKey(), NOW - 100, NOW + 100).sign(otherRoot);
    Handshake a = initiator(alphaCert, alphaId);
    Handshake b = responder(MESH, rootPub, betaForeign, betaId);

    byte[] m1 = a.writeMessage1();
    byte[] m2 = b.readMessage1WriteMessage2(m1);
    assertThrows(Handshake.HandshakeException.class, () -> a.readMessage2WriteMessage3(m2));
  }

  // Certificate-replay defense: a party that presents a genuine, root-signed
  // certificate but does NOT hold the matching identity private key cannot
  // produce a valid transcript signature, so the handshake is rejected. Here
  // the "responder" holds beta's real certificate but signs with a different
  // identity key.
  @Test void partyPresentingACertItDoesNotOwnIsRejected() throws Exception {
    Signer impostorIdentity = Signer.generate(Signer.Level.DSA65, RNG);
    Handshake a = initiator(alphaCert, alphaId);
    Handshake b = responder(MESH, rootPub, betaCert, impostorIdentity); // real cert, wrong key
    byte[] m1 = a.writeMessage1();
    byte[] m2 = b.readMessage1WriteMessage2(m1);
    Handshake.HandshakeException e = assertThrows(Handshake.HandshakeException.class,
        () -> a.readMessage2WriteMessage3(m2));
    assertTrue(e.getMessage().contains("signature"),
        "expected a transcript-signature rejection, got: " + e.getMessage());
  }

  @Test void responderRejectsExpiredInitiatorCertificate() throws Exception {
    Certificate alphaExpired = issue("alpha", alphaId, NOW - 200, NOW - 100);
    Handshake a = initiator(alphaExpired, alphaId);
    Handshake b = responder(MESH, rootPub, betaCert, betaId);
    byte[] m1 = a.writeMessage1();
    byte[] m2 = b.readMessage1WriteMessage2(m1);
    byte[] m3 = a.readMessage2WriteMessage3(m2);
    assertThrows(Handshake.HandshakeException.class, () -> b.readMessage3(m3));
  }

  @Test void tamperedEphemeralBreaksTheHandshake() throws Exception {
    Handshake a = initiator(alphaCert, alphaId);
    Handshake b = responder(MESH, rootPub, betaCert, betaId);
    byte[] m1 = a.writeMessage1();
    byte[] m2 = b.readMessage1WriteMessage2(m1);
    // Flip a byte in the responder's ephemeral field: the initiator derives a
    // different key and cannot open the responder's identity.
    String s = new String(m2, java.nio.charset.StandardCharsets.UTF_8);
    org.json.JSONObject j = new org.json.JSONObject(s);
    byte[] e = java.util.Base64.getDecoder().decode(j.getString("e"));
    e[0] ^= 0x01;
    j.put("e", java.util.Base64.getEncoder().encodeToString(e));
    byte[] tampered = (j.toString() + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8);
    assertThrows(Handshake.HandshakeException.class, () -> a.readMessage2WriteMessage3(tampered));
  }

  @Test void tamperedAuthCiphertextIsRejected() throws Exception {
    Handshake a = initiator(alphaCert, alphaId);
    Handshake b = responder(MESH, rootPub, betaCert, betaId);
    byte[] m1 = a.writeMessage1();
    byte[] m2 = b.readMessage1WriteMessage2(m1);
    org.json.JSONObject j = new org.json.JSONObject(new String(m2, java.nio.charset.StandardCharsets.UTF_8));
    byte[] auth = java.util.Base64.getDecoder().decode(j.getString("auth"));
    auth[auth.length - 1] ^= 0x01; // corrupt the tag
    j.put("auth", java.util.Base64.getEncoder().encodeToString(auth));
    byte[] tampered = (j.toString() + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8);
    assertThrows(Handshake.HandshakeException.class, () -> a.readMessage2WriteMessage3(tampered));
  }
}
