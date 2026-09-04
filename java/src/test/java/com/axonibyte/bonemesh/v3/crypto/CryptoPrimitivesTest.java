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

package com.axonibyte.bonemesh.v3.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

/**
 * Tests for the v3 crypto primitives. The known-answer vectors (RFC 5869,
 * RFC 7748, RFC 8439) are the interop anchors: an implementation in any
 * language that also matches these RFC vectors is byte-compatible with this
 * one, without the two ever having to meet.
 */
public class CryptoPrimitivesTest {

  private static final SecureRandom RNG = new SecureRandom();

  // RFC 5869 Appendix A.1 (HKDF-SHA-256, Test Case 1).
  @Test void hkdfMatchesRfc5869() {
    byte[] ikm = repeat((byte) 0x0b, 22);
    byte[] salt = Hex.decode("000102030405060708090a0b0c");
    byte[] info = Hex.decode("f0f1f2f3f4f5f6f7f8f9");
    byte[] okm = Hkdf.derive(salt, ikm, info, 42);
    assertEquals(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        Hex.toHexString(okm));
  }

  // RFC 7748 §6.1 (X25519), Alice's key pair.
  @Test void x25519MatchesRfc7748() {
    byte[] alicePriv = Hex.decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    Dh alice = Dh.fromPrivate(alicePriv);
    assertEquals(
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        Hex.toHexString(alice.publicKey()));
  }

  @Test void x25519AgreementIsSymmetric() {
    Dh a = Dh.generate(RNG);
    Dh b = Dh.generate(RNG);
    assertArrayEquals(a.agree(b.publicKey()), b.agree(a.publicKey()));
    assertEquals(Dh.KEY_BYTES, a.publicKey().length);
  }

  // RFC 8439 §2.8.2 (ChaCha20-Poly1305 AEAD).
  @Test void chachaPoly1305MatchesRfc8439() throws Exception {
    byte[] key = Hex.decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    byte[] nonce = Hex.decode("070000004041424344454647");
    byte[] aad = Hex.decode("50515253c0c1c2c3c4c5c6c7");
    byte[] pt = ("Ladies and Gentlemen of the class of '99: If I could offer you only "
        + "one tip for the future, sunscreen would be it.").getBytes(StandardCharsets.US_ASCII);
    String expected =
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        + "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        + "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        + "3ff4def08e4b7a9de576d26586cec64b6116"
        + "1ae10b594f09e26a7e902ecbd0600691"; // ciphertext then 16-byte tag
    byte[] sealed = Aead.seal(key, nonce, aad, pt);
    assertEquals(expected, Hex.toHexString(sealed));
    assertArrayEquals(pt, Aead.open(key, nonce, aad, sealed));
  }

  @Test void aeadRejectsTamperedCiphertext() throws Exception {
    byte[] key = repeat((byte) 7, Aead.KEY_BYTES);
    byte[] nonce = repeat((byte) 9, Aead.NONCE_BYTES);
    byte[] sealed = Aead.seal(key, nonce, new byte[0], "secret".getBytes());
    sealed[0] ^= 0x01;
    assertThrows(Aead.AeadException.class, () -> Aead.open(key, nonce, new byte[0], sealed));
  }

  @Test void aeadRejectsWrongAad() throws Exception {
    byte[] key = repeat((byte) 7, Aead.KEY_BYTES);
    byte[] nonce = repeat((byte) 9, Aead.NONCE_BYTES);
    byte[] sealed = Aead.seal(key, nonce, "aad-A".getBytes(), "secret".getBytes());
    assertThrows(Aead.AeadException.class, () -> Aead.open(key, nonce, "aad-B".getBytes(), sealed));
  }

  @Test void mlkemRoundTripsAndHasStandardSizes() {
    Kem responder = Kem.generate(RNG);
    assertEquals(Kem.ENCAP_KEY_BYTES, responder.encapsulationKey().length);
    Kem.Encapsulation e = Kem.encapsulateTo(responder.encapsulationKey(), RNG);
    assertEquals(Kem.CIPHERTEXT_BYTES, e.ciphertext().length);
    assertEquals(Kem.SECRET_BYTES, e.secret().length);
    assertArrayEquals(e.secret(), responder.decapsulate(e.ciphertext()));
  }

  @Test void mldsaSignVerifyRoundTripBothLevels() {
    for(Signer.Level level : Signer.Level.values()) {
      Signer id = Signer.generate(level, RNG);
      byte[] msg = "the transcript hash".getBytes();
      byte[] sig = id.sign(msg);
      assertTrue(Signer.verifier(level, id.publicKey()).verify(msg, sig),
          "valid signature rejected at " + level);
    }
  }

  @Test void mldsaRejectsWrongKeyAndTamperedMessage() {
    Signer a = Signer.generate(Signer.Level.DSA65, RNG);
    Signer b = Signer.generate(Signer.Level.DSA65, RNG);
    byte[] msg = "identity proof".getBytes();
    byte[] sig = a.sign(msg);
    assertFalse(b.verify(msg, sig), "a's signature verified under b's key");
    assertFalse(a.verify("tampered".getBytes(), sig), "signature verified for a different message");
  }

  @Test void mldsaKeysRoundTripThroughRawEncoding() {
    Signer original = Signer.generate(Signer.Level.DSA65, RNG);
    Signer restored = Signer.fromKeys(Signer.Level.DSA65, original.publicKey(), original.privateKey());
    byte[] msg = "persisted".getBytes();
    assertTrue(Signer.verifier(Signer.Level.DSA65, original.publicKey()).verify(msg, restored.sign(msg)));
  }

  private static byte[] repeat(byte b, int n) {
    byte[] out = new byte[n];
    java.util.Arrays.fill(out, b);
    return out;
  }
}
