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

package com.axonibyte.bonemesh.v3.tools;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import com.axonibyte.bonemesh.v3.cert.Certificate;
import com.axonibyte.bonemesh.v3.crypto.Signer;

/**
 * Tests for the CA tool's issuance flow: a certificate issued by a mesh root
 * verifies against that root's public key, and not against a different root.
 */
public class BoneMeshCATest {

  private static final long NOW = 1_788_600_000L;

  @Test void issuedCertificateVerifiesAgainstItsRoot() {
    Signer root = BoneMeshCA.generateRoot();
    Signer node = BoneMeshCA.generateIdentity();
    Certificate cert = BoneMeshCA.issue(root, "acme-prod", "alpha",
        node.publicKey(), NOW - 100, NOW + 100);
    assertDoesNotThrow(() -> cert.verify(root.publicKey(), "acme-prod", NOW));
  }

  @Test void issuedCertificateFailsUnderADifferentRoot() {
    Signer root = BoneMeshCA.generateRoot();
    Signer other = BoneMeshCA.generateRoot();
    Signer node = BoneMeshCA.generateIdentity();
    Certificate cert = BoneMeshCA.issue(root, "acme-prod", "alpha",
        node.publicKey(), NOW - 100, NOW + 100);
    assertThrows(Certificate.CertificateException.class,
        () -> cert.verify(other.publicKey(), "acme-prod", NOW));
  }

  @Test void rootIdentityIsMlDsa87AndNodeIsMlDsa65() {
    org.junit.jupiter.api.Assertions.assertEquals(Signer.Level.DSA87, BoneMeshCA.generateRoot().level());
    org.junit.jupiter.api.Assertions.assertEquals(Signer.Level.DSA65, BoneMeshCA.generateIdentity().level());
  }
}
