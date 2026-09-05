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

package com.axonibyte.bonemesh.v3.transport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;

import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.axonibyte.bonemesh.v3.cert.Certificate;
import com.axonibyte.bonemesh.v3.crypto.Signer;
import com.axonibyte.bonemesh.v3.handshake.Handshake;

/**
 * Transport channel tests over a real handshake: messages round-trip in both
 * directions, and out-of-order, cross-direction, and tampered frames are
 * rejected.
 */
public class TransportSessionTest {

  private static final SecureRandom RNG = new SecureRandom();
  private static final String MESH = "acme-prod";
  private static final long NOW = 1_788_600_000L;

  private TransportSession alpha;
  private TransportSession beta;

  @BeforeEach void setUp() throws Exception {
    Signer root = Signer.generate(Signer.Level.DSA87, RNG);
    byte[] rootPub = root.publicKey();
    Signer aId = Signer.generate(Signer.Level.DSA65, RNG);
    Signer bId = Signer.generate(Signer.Level.DSA65, RNG);
    Certificate aCert = new Certificate(MESH, "alpha", aId.publicKey(), NOW - 100, NOW + 100).sign(root);
    Certificate bCert = new Certificate(MESH, "beta", bId.publicKey(), NOW - 100, NOW + 100).sign(root);

    Handshake a = Handshake.initiator(MESH, rootPub, NOW, aCert, aId, RNG);
    Handshake b = Handshake.responder(MESH, rootPub, NOW, bCert, bId, RNG);
    byte[] m1 = a.writeMessage1();
    byte[] m2 = b.readMessage1WriteMessage2(m1);
    byte[] m3 = a.readMessage2WriteMessage3(m2);
    b.readMessage3(m3);

    alpha = new TransportSession(a.session());
    beta = new TransportSession(b.session());
  }

  @Test void framesRoundTripInBothDirections() throws Exception {
    JSONObject fromA = new JSONObject().put("type", "data").put("line", "hello beta");
    assertEquals("hello beta", beta.open(alpha.seal(fromA)).getString("line"));

    JSONObject fromB = new JSONObject().put("type", "data").put("line", "hi alpha");
    assertEquals("hi alpha", alpha.open(beta.seal(fromB)).getString("line"));

    // A second frame each way advances the sequence without trouble.
    assertEquals("two", beta.open(alpha.seal(new JSONObject().put("line", "two"))).getString("line"));
    assertEquals("2", alpha.open(beta.seal(new JSONObject().put("line", "2"))).getString("line"));
  }

  @Test void outOfOrderFrameIsRejected() throws Exception {
    JSONObject frame0 = alpha.seal(new JSONObject().put("n", 0));
    JSONObject frame1 = alpha.seal(new JSONObject().put("n", 1));
    // Deliver frame 1 before frame 0.
    assertThrows(TransportSession.TransportException.class, () -> beta.open(frame1));
    // Frame 0 in order still works.
    assertEquals(0, beta.open(frame0).getInt("n"));
  }

  @Test void tamperedCiphertextIsRejected() throws Exception {
    JSONObject frame = alpha.seal(new JSONObject().put("secret", "x"));
    byte[] ct = java.util.Base64.getDecoder().decode(frame.getString("ct"));
    ct[ct.length - 1] ^= 0x01; // corrupt the tag
    frame.put("ct", java.util.Base64.getEncoder().encodeToString(ct));
    assertThrows(TransportSession.TransportException.class, () -> beta.open(frame));
  }

  // A frame alpha sealed (with the initiator->responder key) must not open with
  // alpha's own receive key: the two directions have distinct keys.
  @Test void frameDoesNotOpenInTheWrongDirection() throws Exception {
    JSONObject frame = alpha.seal(new JSONObject().put("line", "x"));
    assertThrows(TransportSession.TransportException.class, () -> alpha.open(frame));
  }
}
