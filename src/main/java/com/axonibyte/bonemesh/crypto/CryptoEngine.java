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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.util.encoders.Base64;
import org.json.JSONObject;

/**
 * Manages BoneMesh cryptographic functionality.
 *
 * @author Caleb L. Power <cpower@axonibyte.com>
 */
public class CryptoEngine {

  private PrivateKey privkey = null;
  private PublicKey pubkey = null;
  private Map<String, byte[]> symKeys = new ConcurrentHashMap<>();

  /**
   * Initiates the cryptographic engine with a new keypair.
   *
   * @throws CryptoException if crypto engine failed to be
   *         instantiated with a new Crystal-Kyber keypair
   */
  public CryptoEngine() throws CryptoException {
    try {
      if(null == Security.getProvider("BC"))
        Security.addProvider(new BouncyCastleProvider());
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
      if(null == Security.getProvider("BC"))
        Security.addProvider(new BouncyCastleProvider());
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
   * current asymmetrical keypair, and maps the symmetrical
   * to the node for future use.
   *
   * @param node the name of the node for which the key is to be generated
   * @return a byte array representing the newly-generated symmetrical key
   * @throws CryptoException if the symmetrical and encapsulated keys failed
   *         to be generated properly
   */
  public byte[] encapsulate(String node) throws CryptoException {
    try {
      byte[] key = null;
      final KeyGenerator keygen = KeyGenerator.getInstance("KYBER", "BCPQC");
      keygen.init(new KEMGenerateSpec(pubkey, "AES"), new SecureRandom());
      SecretKeyWithEncapsulation skwe = (SecretKeyWithEncapsulation)keygen.generateKey();
      if(symKeys.containsKey(node))
        symKeys.replace(node, skwe.getEncoded());
      else symKeys.put(node, skwe.getEncoded());
      key = skwe.getEncapsulation();
      return key;
    } catch(Exception e) {
      throw new CryptoException(e);
    }
  }

  /**
   * Decapsulates a symmetrical key from some encapsulated key.
   *
   * @param node the name of the node for which the key is to be decapsulated
   * @param encapsulated the encapsulated key
   * @throws CryptoException if the symmetrical key failed to be decapsulated
   */
  public void decapsulate(String node, byte[] encapsulated) throws CryptoException {
    try {
      final KeyGenerator keygen = KeyGenerator.getInstance("KYBER", "BCPQC");
      keygen.init(new KEMExtractSpec(privkey, encapsulated, "AES"), new SecureRandom());
      byte[] key = ((SecretKeyWithEncapsulation)keygen.generateKey()).getEncoded();
      if(symKeys.containsKey(node))
        symKeys.replace(node, key);
      else symKeys.put(node, key);
    } catch(Exception e) {
      throw new CryptoException(e);
    }
  }

  /**
   * Determines whether or not the node in question is ready to support
   * cryptographic operations e.g. message encryption and decryption.
   *
   * @param node the name of the node in question
   * @return {@code true} iff a symmetrical key corresponding to this
   *                      node is known
   */
  public boolean supportsCrypto(String node) {
    return symKeys.containsKey(node);
  }

  /**
   * Encrypts a JSON payload using the node's symmetrical key.
   *
   * @param node the name of the node that the message is destined for
   * @param message the cleartext message to be encrypted
   * @return a Base64 representation of the ciphertext with IV appended
   * @throws CryptoException if the node was not ready for cryptographic
   *         operation or if the cleartext could not be encrypted
   */
  public String encrypt(String node, JSONObject message) throws CryptoException {
    byte[] key = symKeys.get(node);
    if(null == key) throw new CryptoException("missing symmetric key");
    
    try {
      byte[] iv = new byte[12];
      final var csprng = new SecureRandom();
      csprng.nextBytes(iv);
      
      final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
      byte[] ciphertext = cipher.doFinal(message.toString().getBytes());
      byte[] payload = new byte[ciphertext.length + iv.length];
      System.arraycopy(ciphertext, 0, payload, 0, ciphertext.length);
      System.arraycopy(iv, 0, payload, ciphertext.length, iv.length);

      return new String(Base64.encode(payload));
      
    } catch(Exception e) {
      throw new CryptoException(e);
    }
  }

  /**
   * Decrypts a payload using the node's symmetrical key.
   *
   * @param node the name of the node responsible for sending the message
   * @param message the ciphertext payload with IV appended
   * @return a JSON respresentation of the message in cleartext
   * @throws CryptoException if the node was not ready for cryptographic
   *         operation or if the ciphertext could not be properly decrypted
   *         to some JSON object representation
   */
  public JSONObject decrypt(String node, String message) throws CryptoException {
    byte[] key = symKeys.get(node);
    if(null == key) throw new CryptoException("missing symmetric key");

    try {
      byte[] payload = Base64.decode(message.getBytes());
      byte[] iv = new byte[12];
      if(payload.length <= iv.length)
        throw new CryptoException("ciphertext too short");
      byte[] ciphertext = new byte[payload.length - iv.length];
      System.arraycopy(payload, 0, ciphertext, 0, payload.length - iv.length);
      System.arraycopy(payload, payload.length - iv.length, iv, 0, iv.length);

      final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
      
      return new JSONObject(new String(cipher.doFinal()));
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
  public class CryptoException extends RuntimeException {
    private CryptoException(Throwable cause) {
      super(cause);
    }

    private CryptoException(String message) {
      super(message);
    }

    private CryptoException(String message, Throwable cause) {
      super(message, cause);
    }
  }
  
}
