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
import java.security.MessageDigest;
import java.util.Arrays;

import com.axonibyte.bonemesh.v3.crypto.Aead;
import com.axonibyte.bonemesh.v3.crypto.Hkdf;

/**
 * The BMX key schedule (security.md &sect;5): a Noise-style symmetric state
 * carrying a transcript hash {@code h} and a chaining key {@code ck}, driving
 * SHA-256 / HKDF-SHA-256 / ChaCha20-Poly1305. These operations and their
 * constants are PINNED — the shared key-schedule vector
 * (spec/corpus/transcripts/keyschedule.json) freezes them, and the Go
 * conformance runner reproduces them, so both languages derive identical keys.
 *
 * <p>Conventions, all pinned:</p>
 * <ul>
 *   <li>protocol name seeds {@code h} and {@code ck} via SHA-256;</li>
 *   <li>{@code mixHash(d): h = SHA-256(h || d)};</li>
 *   <li>{@code mixKey(ikm): (ck, k) = HKDF-SHA-256(salt=ck, ikm, info="", 64)},
 *       nonce reset to 0;</li>
 *   <li>AEAD nonce = 4 zero bytes then the 64-bit little-endian counter;</li>
 *   <li>{@code encryptAndHash}/{@code decryptAndHash} use {@code h} as AEAD
 *       associated data, then {@code mixHash(ciphertext)};</li>
 *   <li>{@code split(): (k1, k2) = HKDF-SHA-256(salt=ck, ikm="", info="", 64)}.</li>
 * </ul>
 *
 * @author Caleb L. Power
 */
public final class SymmetricState {

  /** The pinned BMX protocol name (security.md &sect;5). */
  public static final String PROTOCOL_NAME = "BoneMesh_BMX_v3_X25519MLKEM768_ChaChaPoly_SHA256";

  private byte[] h;
  private byte[] ck;
  private byte[] key;    // current AEAD key, null until the first mixKey
  private long nonce;    // AEAD nonce counter for the current key

  /**
   * Initializes the state from the pinned protocol name.
   */
  public SymmetricState() {
    this.h = sha256(PROTOCOL_NAME.getBytes(StandardCharsets.UTF_8));
    this.ck = h.clone();
    this.key = null;
    this.nonce = 0;
  }

  /**
   * Absorbs data into the transcript hash: {@code h = SHA-256(h || data)}.
   *
   * @param data the bytes to absorb
   */
  public void mixHash(byte[] data) {
    byte[] combined = new byte[h.length + data.length];
    System.arraycopy(h, 0, combined, 0, h.length);
    System.arraycopy(data, 0, combined, h.length, data.length);
    h = sha256(combined);
  }

  /**
   * Mixes input key material into the chaining key, deriving a fresh AEAD key
   * and resetting the nonce.
   *
   * @param ikm the input key material (e.g. a Diffie-Hellman or KEM secret)
   */
  public void mixKey(byte[] ikm) {
    byte[] okm = Hkdf.derive(ck, ikm, new byte[0], 64);
    ck = Arrays.copyOfRange(okm, 0, 32);
    key = Arrays.copyOfRange(okm, 32, 64);
    nonce = 0;
  }

  /**
   * Encrypts {@code plaintext} under the current key with {@code h} as
   * associated data, then absorbs the ciphertext into the transcript.
   *
   * @param plaintext the plaintext
   * @return the ciphertext (with appended tag)
   */
  public byte[] encryptAndHash(byte[] plaintext) {
    requireKey();
    byte[] ciphertext = Aead.seal(key, nextNonce(), h, plaintext);
    mixHash(ciphertext);
    return ciphertext;
  }

  /**
   * Decrypts {@code ciphertext} under the current key with {@code h} as
   * associated data, then absorbs the ciphertext into the transcript.
   *
   * @param ciphertext the ciphertext (with appended tag)
   * @return the recovered plaintext
   * @throws Aead.AeadException if the tag does not verify
   */
  public byte[] decryptAndHash(byte[] ciphertext) throws Aead.AeadException {
    requireKey();
    byte[] adBefore = h; // AEAD associated data is h prior to absorbing this ciphertext
    byte[] plaintext = Aead.open(key, nextNonce(), adBefore, ciphertext);
    mixHash(ciphertext);
    return plaintext;
  }

  /**
   * Derives the two directional transport keys from the final chaining key.
   *
   * @return a two-element array: [initiator&rarr;responder, responder&rarr;initiator]
   */
  public byte[][] split() {
    byte[] okm = Hkdf.derive(ck, new byte[0], new byte[0], 64);
    return new byte[][] { Arrays.copyOfRange(okm, 0, 32), Arrays.copyOfRange(okm, 32, 64) };
  }

  /** @return a copy of the current transcript hash */
  public byte[] transcriptHash() {
    return h.clone();
  }

  /** @return a copy of the current chaining key (for test vectors) */
  public byte[] chainingKey() {
    return ck.clone();
  }

  private void requireKey() {
    if(key == null) throw new IllegalStateException("no key material has been mixed yet");
  }

  /**
   * The current AEAD nonce counter. Package-private, for tests that assert the
   * counter resets on {@link #mixKey(byte[])} — the invariant that keeps a
   * rekey from reusing a nonce, which the single-pass handshake alone does not
   * exercise.
   *
   * @return the next nonce value that would be used
   */
  long nonceCounter() {
    return nonce;
  }

  // Nonce = 4 zero bytes || little-endian uint64(counter), then increment.
  private byte[] nextNonce() {
    byte[] n = new byte[Aead.NONCE_BYTES];
    long v = nonce++;
    for(int i = 0; i < 8; i++) n[4 + i] = (byte) (v >>> (8 * i));
    return n;
  }

  private static byte[] sha256(byte[] input) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(input);
    } catch(java.security.NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }
}
