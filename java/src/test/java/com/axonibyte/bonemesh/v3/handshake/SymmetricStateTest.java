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
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * Correctness and composition tests for the BMX key schedule. The exact shared
 * vector is reproduced independently by the Go runner and re-checked on the
 * driver by {@code interop/check-keyschedule.sh}; this suite proves the schedule
 * is correct (against the SHA-256 formula) and that an initiator/responder pair
 * stays in lockstep through encrypt/decrypt.
 */
public class SymmetricStateTest {

  private static byte[] sha256(byte[] b) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(b);
  }

  @Test void initSeedsHashFromProtocolName() throws Exception {
    SymmetricState s = new SymmetricState();
    assertArrayEquals(sha256(SymmetricState.PROTOCOL_NAME.getBytes(StandardCharsets.UTF_8)),
        s.transcriptHash());
  }

  @Test void mixHashFollowsTheFormula() throws Exception {
    SymmetricState s = new SymmetricState();
    byte[] h0 = s.transcriptHash();
    byte[] data = "some-transcript-bytes".getBytes();
    s.mixHash(data);
    byte[] combined = new byte[h0.length + data.length];
    System.arraycopy(h0, 0, combined, 0, h0.length);
    System.arraycopy(data, 0, combined, h0.length, data.length);
    assertArrayEquals(sha256(combined), s.transcriptHash());
  }

  @Test void sameInputsYieldSameChainingKey() {
    assertArrayEquals(driven().chainingKey(), driven().chainingKey());
  }

  @Test void differentInputsDivergeChainingKey() {
    SymmetricState a = new SymmetricState();
    SymmetricState b = new SymmetricState();
    a.mixKey(repeat((byte) 1));
    b.mixKey(repeat((byte) 2));
    assertFalse(Arrays.equals(a.chainingKey(), b.chainingKey()));
  }

  // An initiator and responder that ran the same key schedule stay in lockstep:
  // what one encrypts, the other decrypts, across two messages (exercising the
  // nonce counter), and their transcript hashes and split keys stay equal.
  @Test void initiatorAndResponderStayInLockstep() throws Exception {
    SymmetricState initiator = driven();
    SymmetricState responder = driven();

    byte[] m1 = "responder sees this".getBytes();
    byte[] ct1 = initiator.encryptAndHash(m1);
    assertArrayEquals(m1, responder.decryptAndHash(ct1));

    byte[] m2 = "and this second one".getBytes();
    byte[] ct2 = initiator.encryptAndHash(m2);
    assertArrayEquals(m2, responder.decryptAndHash(ct2));

    assertArrayEquals(initiator.transcriptHash(), responder.transcriptHash());
    byte[][] ik = initiator.split();
    byte[][] rk = responder.split();
    assertArrayEquals(ik[0], rk[0]);
    assertArrayEquals(ik[1], rk[1]);
  }

  // The nonce counter must reset when a new key is mixed, so a rekey never
  // reuses a nonce. BMX itself mixes all keys before encrypting, so this
  // invariant is otherwise unexercised until transport rekeying (§6) uses it.
  @Test void mixKeyResetsTheNonceCounter() {
    SymmetricState s = new SymmetricState();
    s.mixKey(ramp(1));
    s.encryptAndHash("first".getBytes());
    org.junit.jupiter.api.Assertions.assertEquals(1L, s.nonceCounter(),
        "encrypt should advance the nonce");
    s.mixKey(ramp(0x21));
    org.junit.jupiter.api.Assertions.assertEquals(0L, s.nonceCounter(),
        "a fresh key must reset the nonce to 0");
  }

  // A tampered ciphertext must fail authentication on the receiver.
  @Test void tamperedCiphertextFailsToDecrypt() {
    SymmetricState initiator = driven();
    SymmetricState responder = driven();
    byte[] ct = initiator.encryptAndHash("payload".getBytes());
    ct[0] ^= 0x01;
    org.junit.jupiter.api.Assertions.assertThrows(
        com.axonibyte.bonemesh.v3.crypto.Aead.AeadException.class,
        () -> responder.decryptAndHash(ct));
  }

  private static SymmetricState driven() {
    SymmetricState s = new SymmetricState();
    s.mixHash("acme-prod".getBytes());
    s.mixKey(ramp(1));
    s.mixKey(ramp(0x21));
    return s;
  }

  private static byte[] ramp(int start) {
    byte[] b = new byte[32];
    for(int i = 0; i < 32; i++) b[i] = (byte) (start + i);
    return b;
  }

  private static byte[] repeat(byte v) {
    byte[] b = new byte[32];
    Arrays.fill(b, v);
    return b;
  }
}
