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

import java.security.SecureRandom;

import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

/**
 * An ephemeral X25519 key pair (RFC 7748), one half of the BoneMesh v3 hybrid
 * key agreement (security.md &sect;4). Public keys and shared secrets are the
 * raw 32-byte encodings, matching Go's {@code crypto/ecdh} and RustCrypto, so
 * the agreement is cross-language.
 *
 * @author Caleb L. Power
 */
public final class Dh {

  /** Raw X25519 public key / shared secret length in bytes. */
  public static final int KEY_BYTES = 32;

  private final X25519PrivateKeyParameters privateKey;
  private final X25519PublicKeyParameters publicKey;

  private Dh(X25519PrivateKeyParameters privateKey) {
    this.privateKey = privateKey;
    this.publicKey = privateKey.generatePublicKey();
  }

  /**
   * Generates a fresh ephemeral key pair.
   *
   * @param rng the randomness source
   * @return a new key pair
   */
  public static Dh generate(SecureRandom rng) {
    X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
    gen.init(new X25519KeyGenerationParameters(rng));
    return new Dh((X25519PrivateKeyParameters) gen.generateKeyPair().getPrivate());
  }

  /**
   * Reconstructs a key pair from a raw 32-byte private scalar (for test
   * vectors and persistence).
   *
   * @param rawPrivate the 32-byte private key
   * @return the key pair
   */
  public static Dh fromPrivate(byte[] rawPrivate) {
    if(rawPrivate == null || rawPrivate.length != KEY_BYTES)
      throw new IllegalArgumentException("private key must be " + KEY_BYTES + " bytes");
    return new Dh(new X25519PrivateKeyParameters(rawPrivate, 0));
  }

  /**
   * @return the raw 32-byte public key
   */
  public byte[] publicKey() {
    return publicKey.getEncoded();
  }

  /**
   * Computes the raw 32-byte shared secret with a peer's public key.
   *
   * @param peerPublicKey the peer's raw 32-byte public key
   * @return the shared secret
   */
  public byte[] agree(byte[] peerPublicKey) {
    if(peerPublicKey == null || peerPublicKey.length != KEY_BYTES)
      throw new IllegalArgumentException("peer public key must be " + KEY_BYTES + " bytes");
    X25519Agreement agreement = new X25519Agreement();
    agreement.init(privateKey);
    byte[] secret = new byte[agreement.getAgreementSize()];
    agreement.calculateAgreement(new X25519PublicKeyParameters(peerPublicKey, 0), secret, 0);
    return secret;
  }
}
