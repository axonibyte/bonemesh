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

import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

/**
 * An ML-DSA signing identity (FIPS 204). BoneMesh v3 uses ML-DSA-65 for node
 * identities and ML-DSA-87 for the mesh root (security.md &sect;1). Public and
 * private keys are the raw FIPS-204 encodings, matching other implementations.
 *
 * @author Caleb L. Power
 */
public final class Signer {

  /** Which ML-DSA parameter set an identity uses. */
  public enum Level {
    /** ML-DSA-65 (FIPS 204, category 3) — node identities. */
    DSA65(MLDSAParameters.ml_dsa_65),
    /** ML-DSA-87 (FIPS 204, category 5) — the mesh root. */
    DSA87(MLDSAParameters.ml_dsa_87);

    private final MLDSAParameters params;

    Level(MLDSAParameters params) {
      this.params = params;
    }
  }

  private final Level level;
  private final MLDSAPublicKeyParameters publicKey;
  private final MLDSAPrivateKeyParameters privateKey; // null for a verify-only identity

  private Signer(Level level, MLDSAPublicKeyParameters publicKey, MLDSAPrivateKeyParameters privateKey) {
    this.level = level;
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  /**
   * Generates a fresh signing identity at the given level.
   *
   * @param level the parameter set
   * @param rng the randomness source
   * @return a new identity holding both keys
   */
  public static Signer generate(Level level, SecureRandom rng) {
    MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
    gen.init(new MLDSAKeyGenerationParameters(rng, level.params));
    var kp = gen.generateKeyPair();
    return new Signer(level, (MLDSAPublicKeyParameters) kp.getPublic(),
        (MLDSAPrivateKeyParameters) kp.getPrivate());
  }

  /**
   * Reconstructs a signing identity from raw key bytes.
   *
   * @param level the parameter set
   * @param rawPublic the raw public key
   * @param rawPrivate the raw private key
   * @return an identity able to sign and verify
   */
  public static Signer fromKeys(Level level, byte[] rawPublic, byte[] rawPrivate) {
    return new Signer(level,
        new MLDSAPublicKeyParameters(level.params, rawPublic),
        new MLDSAPrivateKeyParameters(level.params, rawPrivate));
  }

  /**
   * Reconstructs a verify-only identity from a raw public key.
   *
   * @param level the parameter set
   * @param rawPublic the raw public key
   * @return an identity able only to verify
   */
  public static Signer verifier(Level level, byte[] rawPublic) {
    return new Signer(level, new MLDSAPublicKeyParameters(level.params, rawPublic), null);
  }

  /**
   * @return the raw public key
   */
  public byte[] publicKey() {
    return publicKey.getEncoded();
  }

  /**
   * @return the raw private key
   * @throws IllegalStateException if this identity is verify-only
   */
  public byte[] privateKey() {
    if(privateKey == null) throw new IllegalStateException("verify-only identity has no private key");
    return privateKey.getEncoded();
  }

  /**
   * Signs a message.
   *
   * @param message the message bytes
   * @return the ML-DSA signature
   * @throws IllegalStateException if this identity is verify-only
   */
  public byte[] sign(byte[] message) {
    if(privateKey == null) throw new IllegalStateException("verify-only identity cannot sign");
    MLDSASigner signer = new MLDSASigner();
    signer.init(true, privateKey);
    signer.update(message, 0, message.length);
    try {
      return signer.generateSignature();
    } catch(org.bouncycastle.crypto.CryptoException e) {
      throw new IllegalStateException("ML-DSA signing failed", e);
    }
  }

  /**
   * Verifies a signature against this identity's public key.
   *
   * @param message the message bytes
   * @param signature the candidate signature
   * @return <code>true</code> iff the signature is valid
   */
  public boolean verify(byte[] message, byte[] signature) {
    MLDSASigner verifier = new MLDSASigner();
    verifier.init(false, publicKey);
    verifier.update(message, 0, message.length);
    return verifier.verifySignature(signature);
  }

  /**
   * @return the parameter level of this identity
   */
  public Level level() {
    return level;
  }
}
