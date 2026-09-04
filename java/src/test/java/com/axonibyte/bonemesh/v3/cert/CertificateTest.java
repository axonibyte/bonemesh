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

package com.axonibyte.bonemesh.v3.cert;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.axonibyte.bonemesh.v3.cert.Certificate.CertificateException;
import com.axonibyte.bonemesh.v3.crypto.Signer;

/**
 * Membership certificate sign/verify tests (security.md §3).
 */
public class CertificateTest {

  private static final SecureRandom RNG = new SecureRandom();
  private static final long NOW = 1_788_600_000L;

  private Signer root;
  private byte[] rootPub;
  private Signer node;

  @BeforeEach void setUp() {
    root = Signer.generate(Signer.Level.DSA87, RNG);
    rootPub = root.publicKey();
    node = Signer.generate(Signer.Level.DSA65, RNG);
  }

  private Certificate cert(long nbf, long exp) {
    return new Certificate("acme-prod", "alpha", node.publicKey(), nbf, exp);
  }

  @Test void signedCertVerifies() {
    Certificate c = cert(NOW - 100, NOW + 100).sign(root);
    assertDoesNotThrow(() -> c.verify(rootPub, "acme-prod", NOW));
  }

  @Test void unsignedCertIsRejected() {
    CertificateException e = assertThrows(CertificateException.class,
        () -> cert(NOW - 100, NOW + 100).verify(rootPub, "acme-prod", NOW));
    assertEquals("certificate is unsigned", e.getMessage());
  }

  @Test void expiredCertIsRejected() {
    Certificate c = cert(NOW - 200, NOW - 100).sign(root);
    assertThrows(CertificateException.class, () -> c.verify(rootPub, "acme-prod", NOW));
  }

  @Test void notYetValidCertIsRejected() {
    Certificate c = cert(NOW + 100, NOW + 200).sign(root);
    assertThrows(CertificateException.class, () -> c.verify(rootPub, "acme-prod", NOW));
  }

  @Test void meshMismatchIsRejected() {
    Certificate c = cert(NOW - 100, NOW + 100).sign(root);
    assertThrows(CertificateException.class, () -> c.verify(rootPub, "other-mesh", NOW));
  }

  @Test void wrongRootKeyIsRejected() {
    Certificate c = cert(NOW - 100, NOW + 100).sign(root);
    byte[] impostorRootPub = Signer.generate(Signer.Level.DSA87, RNG).publicKey();
    assertThrows(CertificateException.class, () -> c.verify(impostorRootPub, "acme-prod", NOW));
  }

  // A certificate whose identity key is altered after signing must fail: the
  // signature covers the canonical bytes, which include idk.
  @Test void tamperedIdentityKeyIsRejected() throws Exception {
    Certificate c = cert(NOW - 100, NOW + 100).sign(root);
    org.json.JSONObject j = c.toJSON();
    byte[] otherKey = Signer.generate(Signer.Level.DSA65, RNG).publicKey();
    j.put("idk", java.util.Base64.getEncoder().encodeToString(otherKey));
    Certificate tampered = Certificate.fromJSON(j);
    assertThrows(CertificateException.class, () -> tampered.verify(rootPub, "acme-prod", NOW));
  }

  @Test void jsonRoundTripPreservesEverything() throws Exception {
    Certificate c = cert(NOW - 100, NOW + 100).sign(root);
    Certificate back = Certificate.fromJSON(c.toJSON());
    assertEquals(c.label(), back.label());
    assertEquals(c.mesh(), back.mesh());
    assertArrayEquals(c.identityKey(), back.identityKey());
    assertArrayEquals(c.canonicalBytes(), back.canonicalBytes());
    assertDoesNotThrow(() -> back.verify(rootPub, "acme-prod", NOW));
  }
}
