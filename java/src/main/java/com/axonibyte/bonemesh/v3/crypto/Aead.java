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

import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * ChaCha20-Poly1305 AEAD (RFC 8439), the BoneMesh v3 transport and handshake
 * cipher (security.md &sect;11). 256-bit key, 96-bit nonce, 128-bit tag
 * appended to the ciphertext. Byte-compatible with any conforming RFC 8439
 * implementation, which is what lets a Go or Rust node open what a Java node
 * sealed.
 *
 * @author Caleb L. Power
 */
public final class Aead {

  /** AEAD key length in bytes. */
  public static final int KEY_BYTES = 32;
  /** AEAD nonce length in bytes. */
  public static final int NONCE_BYTES = 12;
  /** Poly1305 tag length in bytes. */
  public static final int TAG_BYTES = 16;

  private Aead() { }

  /**
   * Seals plaintext, returning ciphertext with the 16-byte tag appended.
   *
   * @param key the 32-byte key
   * @param nonce the 12-byte nonce (never reused under one key)
   * @param aad additional authenticated data (may be empty, not null)
   * @param plaintext the plaintext
   * @return ciphertext concatenated with the authentication tag
   */
  public static byte[] seal(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext) {
    requireLengths(key, nonce);
    ChaCha20Poly1305 cipher = new ChaCha20Poly1305();
    cipher.init(true, new AEADParameters(new KeyParameter(key), TAG_BYTES * 8, nonce, aad));
    byte[] out = new byte[cipher.getOutputSize(plaintext.length)];
    int off = cipher.processBytes(plaintext, 0, plaintext.length, out, 0);
    try {
      cipher.doFinal(out, off);
    } catch(Exception e) {
      throw new IllegalStateException("AEAD seal failed", e);
    }
    return out;
  }

  /**
   * Opens ciphertext (with appended tag), verifying the tag.
   *
   * @param key the 32-byte key
   * @param nonce the 12-byte nonce
   * @param aad additional authenticated data (must match what was sealed)
   * @param ciphertext ciphertext with the 16-byte tag appended
   * @return the recovered plaintext
   * @throws AeadException if the tag does not verify or inputs are malformed
   */
  public static byte[] open(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext)
      throws AeadException {
    requireLengths(key, nonce);
    if(ciphertext.length < TAG_BYTES)
      throw new AeadException("ciphertext shorter than the tag");
    ChaCha20Poly1305 cipher = new ChaCha20Poly1305();
    cipher.init(false, new AEADParameters(new KeyParameter(key), TAG_BYTES * 8, nonce, aad));
    byte[] out = new byte[cipher.getOutputSize(ciphertext.length)];
    int off = cipher.processBytes(ciphertext, 0, ciphertext.length, out, 0);
    try {
      cipher.doFinal(out, off);
    } catch(Exception e) {
      throw new AeadException("AEAD tag verification failed");
    }
    return out;
  }

  private static void requireLengths(byte[] key, byte[] nonce) {
    if(key == null || key.length != KEY_BYTES)
      throw new IllegalArgumentException("key must be " + KEY_BYTES + " bytes");
    if(nonce == null || nonce.length != NONCE_BYTES)
      throw new IllegalArgumentException("nonce must be " + NONCE_BYTES + " bytes");
  }

  /** Thrown when AEAD decryption fails, most importantly on tag mismatch. */
  public static final class AeadException extends Exception {
    AeadException(String message) {
      super(message);
    }
  }
}
