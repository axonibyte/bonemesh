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

package com.axonibyte.bonemesh.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.bouncycastle.util.encoders.Base64;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import com.axonibyte.bonemesh.crypto.CryptoEngine.CryptoException;

/**
 * Round-trip tests for the ML-KEM + AES/GCM prototype engine.
 *
 * What this suite does not prove: resistance to an active attacker. Key
 * distribution rides unsigned discovery traffic (defect D8) and is redesigned
 * in the v3 spec; these tests only pin the mechanical KEM/AEAD round trip
 * that every BoneMesh.build() depends on.
 */
public class CryptoEngineTest {

  @Test void encapsulateDecapsulateEncryptDecryptRoundTrip() throws Exception {
    CryptoEngine alice = new CryptoEngine();
    CryptoEngine bob = new CryptoEngine();

    byte[] encapsulated = alice.encapsulate("bob", new String(Base64.encode(bob.getPubkey())));
    bob.decapsulate("alice", encapsulated);
    assertTrue(alice.supportsCrypto("bob"));
    assertTrue(bob.supportsCrypto("alice"));

    JSONObject cleartext = new JSONObject().put("line", "hello, bob");
    String ciphertext = alice.encrypt("bob", cleartext);
    assertFalse(ciphertext.contains("hello, bob"), "payload leaked in the clear");
    JSONObject decrypted = bob.decrypt("alice", ciphertext);
    assertEquals("hello, bob", decrypted.getString("line"));
  }

  @Test void persistedKeypairStillDecapsulates() throws Exception {
    CryptoEngine original = new CryptoEngine();
    CryptoEngine reloaded = new CryptoEngine(original.getPrivkey(), original.getPubkey());
    CryptoEngine peer = new CryptoEngine();

    byte[] encapsulated = peer.encapsulate("them", new String(Base64.encode(reloaded.getPubkey())));
    reloaded.decapsulate("peer", encapsulated);
    JSONObject decrypted = reloaded.decrypt("peer", peer.encrypt("them", new JSONObject().put("k", "v")));
    assertEquals("v", decrypted.getString("k"));
  }

  @Test void distinctEnginesGetDistinctKeypairs() throws Exception {
    assertNotEquals(
        new String(Base64.encode(new CryptoEngine().getPubkey())),
        new String(Base64.encode(new CryptoEngine().getPubkey())));
  }

  @Test void encryptingWithoutAKeyIsRefused() throws Exception {
    CryptoEngine engine = new CryptoEngine();
    assertFalse(engine.supportsCrypto("stranger"));
    assertThrows(CryptoException.class,
        () -> engine.encrypt("stranger", new JSONObject().put("k", "v")));
  }
}
