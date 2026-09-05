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

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

/**
 * An ephemeral ML-KEM-768 key pair (FIPS 203), the post-quantum half of the
 * BoneMesh v3 hybrid key agreement (security.md &sect;4). Encapsulation keys,
 * ciphertexts, and shared secrets are the raw FIPS-203 byte strings (1184 /
 * 1088 / 32 bytes), matching Go's {@code crypto/mlkem}.
 *
 * @author Caleb L. Power
 */
public final class Kem {

  /** Raw ML-KEM-768 encapsulation (public) key length in bytes. */
  public static final int ENCAP_KEY_BYTES = 1184;
  /** Raw ML-KEM-768 ciphertext length in bytes. */
  public static final int CIPHERTEXT_BYTES = 1088;
  /** Shared secret length in bytes. */
  public static final int SECRET_BYTES = 32;

  private final MLKEMPublicKeyParameters publicKey;
  private final MLKEMPrivateKeyParameters privateKey;

  private Kem(MLKEMPublicKeyParameters publicKey, MLKEMPrivateKeyParameters privateKey) {
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  /**
   * Generates a fresh ephemeral ML-KEM-768 key pair.
   *
   * @param rng the randomness source
   * @return a new key pair
   */
  public static Kem generate(SecureRandom rng) {
    MLKEMKeyPairGenerator gen = new MLKEMKeyPairGenerator();
    gen.init(new MLKEMKeyGenerationParameters(rng, MLKEMParameters.ml_kem_768));
    var kp = gen.generateKeyPair();
    return new Kem((MLKEMPublicKeyParameters) kp.getPublic(),
        (MLKEMPrivateKeyParameters) kp.getPrivate());
  }

  /**
   * @return the raw encapsulation (public) key
   */
  public byte[] encapsulationKey() {
    return publicKey.getEncoded();
  }

  /**
   * @return the raw decapsulation (private) key, for test vectors and
   *         persistence
   */
  public byte[] decapsulationKey() {
    return privateKey.getEncoded();
  }

  /**
   * Encapsulates a fresh shared secret to a peer's encapsulation key.
   *
   * @param peerEncapsulationKey the peer's raw encapsulation key
   * @param rng the randomness source
   * @return the ciphertext to send and the shared secret to keep
   */
  public static Encapsulation encapsulateTo(byte[] peerEncapsulationKey, SecureRandom rng) {
    if(peerEncapsulationKey == null || peerEncapsulationKey.length != ENCAP_KEY_BYTES)
      throw new IllegalArgumentException("encapsulation key must be " + ENCAP_KEY_BYTES + " bytes");
    MLKEMPublicKeyParameters pub =
        new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, peerEncapsulationKey);
    SecretWithEncapsulation swe = new MLKEMGenerator(rng).generateEncapsulated(pub);
    return new Encapsulation(swe.getEncapsulation(), swe.getSecret());
  }

  /**
   * Recovers the shared secret from a ciphertext encapsulated to this key pair.
   *
   * @param ciphertext the raw ML-KEM ciphertext
   * @return the shared secret
   */
  public byte[] decapsulate(byte[] ciphertext) {
    if(ciphertext == null || ciphertext.length != CIPHERTEXT_BYTES)
      throw new IllegalArgumentException("ciphertext must be " + CIPHERTEXT_BYTES + " bytes");
    return new MLKEMExtractor(privateKey).extractSecret(ciphertext);
  }

  /** A ciphertext to transmit paired with the shared secret it establishes. */
  public static final class Encapsulation {
    private final byte[] ciphertext;
    private final byte[] secret;

    Encapsulation(byte[] ciphertext, byte[] secret) {
      this.ciphertext = ciphertext;
      this.secret = secret;
    }

    /** @return the raw ciphertext to send to the peer */
    public byte[] ciphertext() {
      return ciphertext;
    }

    /** @return the shared secret to keep */
    public byte[] secret() {
      return secret;
    }
  }
}
