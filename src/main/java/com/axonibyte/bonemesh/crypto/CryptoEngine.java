/*
 * Copyright (c) 2019 Axonibyte Innovations, LLC. All rights reserved.
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

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

/**
 * Manages BoneMesh cryptographic functionality.
 *
 * @author Caleb L. Power <cpower@axonibyte.com>
 */
public class CryptoEngine {

  private PrivateKey privkey = null;
  private PublicKey pubkey = null;

  /**
   * Initiates the cryptographic engine with a new keypair.
   *
   * @throws CryptoException if crypto engine failed to be
   *         instantiated with a new Crystal-Kyber keypair
   */
  public CryptoEngine() throws CryptoException {
    try {
      if(null == Security.getProvider("BCPQC"))
        Security.addProvider(new BouncyCastlePQCProvider());
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("KYBER", "BCPQC");
      kpg.initialize(KyberParameterSpec.kyber1024, new SecureRandom());
      KeyPair kp = kpg.generateKeyPair();
      this.privkey = kp.getPrivate();
      this.pubkey = kp.getPublic();
    } catch(Exception e) {
      throw new CryptoException(e);
    }
  }

  /**
   * Initiates the cryptographic engine with an existing keypair.
   *
   * @param privkey a byte array representing the private key
   * @param pubkey a byte array representing the public key
   * @throws CryptoException if crypto engine failed to be
   *         instantiated with ane xisting Crystal-Kyber keypair
   */
  public CryptoEngine(byte[] privkey, byte[] pubkey) throws CryptoException {
    try {
      if(null == Security.getProvider("BCPQC"))
        Security.addProvider(new BouncyCastlePQCProvider());
      PKCS8EncodedKeySpec pkcs8EKS = new PKCS8EncodedKeySpec(privkey);
      X509EncodedKeySpec x509EKS = new X509EncodedKeySpec(pubkey);
      KeyFactory kf = KeyFactory.getInstance("KYBER", "BCPQC");
      this.privkey = kf.generatePrivate(pkcs8EKS);
      this.pubkey = kf.generatePublic(x509EKS);
    } catch(Exception e) {
      throw new CryptoException(e);
    }
  }

  /**
   * Retrieves the private key.
   *
   * @return a byte array representing the private key
   */
  public byte[] getPrivkey() {
    return privkey.getEncoded();
  }

  /**
   * Retrieves the public key.
   *
   * @return a byte array representing the public key
   */
  public byte[] getPubkey() {
    return pubkey.getEncoded();
  }

  /**
   * Encapsulates a new symmetrical key, derived from the
   * current asymmetrical keypair.
   *
   * @return a double byte array, where element 0 describes the encoded
   *         (secret) key and element 1 describes the encapsulated
   *         (shared) key
   * @throws CryptoException if the symmetrical and encapsulated keys failed
   *         to be generated properly
   */
  public byte[][] encapsulate() throws CryptoException {
    try {
      byte[][] keys = new byte[2][];
      final KeyGenerator keygen = KeyGenerator.getInstance("KYBER", "BCPQC");
      keygen.init(new KEMGenerateSpec(pubkey, "AES"), new SecureRandom());
      SecretKeyWithEncapsulation skwe = (SecretKeyWithEncapsulation)keygen.generateKey();
      keys[0] = skwe.getEncoded();
      keys[1] = skwe.getEncapsulation();
      return keys;
    } catch(Exception e) {
      throw new CryptoException(e);
    }
  }

  /**
   * Decapsulates a symmetrical key from some encapsulated key.
   *
   * @return a byte array representing a secret symmetrical key
   * @throws CryptoException if the symmetrical key failed to be decapsulated
   */
  public byte[] decapsulate(byte[] encapsulated) throws CryptoException {
    try {
      byte[] key = null;
      final KeyGenerator keygen = KeyGenerator.getInstance("KYBER", "BCPQC");
      keygen.init(new KEMExtractSpec(privkey, encapsulated, "AES"), new SecureRandom());
      key = ((SecretKeyWithEncapsulation)keygen.generateKey()).getEncoded();
      return key;
    } catch(Exception e) {
      throw new CryptoException(e);
    }
  }

  /**
   * An exception to be thrown in the event of a cryptographical failure
   * or a failure in its dependencies.
   *
   * @author Caleb L. Power <cpower@axonibyte.com>
   */
  public class CryptoException extends Exception {
    CryptoException(Throwable cause) {
      super(cause);
    }
  }
  
}
