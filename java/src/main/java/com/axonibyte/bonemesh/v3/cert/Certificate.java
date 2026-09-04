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

package com.axonibyte.bonemesh.v3.cert;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import org.json.JSONObject;

import com.axonibyte.bonemesh.v3.crypto.Signer;

/**
 * A BoneMesh v3 membership certificate (security.md &sect;3): a mesh-root-signed
 * binding of a display label to a node's ML-DSA-65 identity key, valid within a
 * time window. The certificate is JSON (human-readable); its signed pre-image is
 * the {@link Jcs} canonicalization of every field except {@code sig}.
 *
 * @author Caleb L. Power
 */
public final class Certificate {

  /** The only supported certificate version. */
  public static final int VERSION = 3;

  private static final Base64.Encoder B64ENC = Base64.getEncoder();
  private static final Base64.Decoder B64DEC = Base64.getDecoder();

  private final String mesh;
  private final String label;
  private final byte[] identityKey; // raw ML-DSA-65 public key
  private final long notBefore;
  private final long notAfter;
  private String signature; // base64 ML-DSA-87 root signature, null until signed

  /**
   * Constructs an unsigned certificate.
   *
   * @param mesh the mesh identifier
   * @param label the node's display label
   * @param identityKey the node's raw ML-DSA-65 public key
   * @param notBefore validity start (Unix seconds)
   * @param notAfter validity end (Unix seconds)
   */
  public Certificate(String mesh, String label, byte[] identityKey, long notBefore, long notAfter) {
    this.mesh = mesh;
    this.label = label;
    this.identityKey = identityKey.clone();
    this.notBefore = notBefore;
    this.notAfter = notAfter;
  }

  /** @return the canonical signed pre-image bytes (security.md §11.1) */
  public byte[] canonicalBytes() {
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("v", (long) VERSION);
    m.put("mesh", mesh);
    m.put("label", label);
    m.put("idk", B64ENC.encodeToString(identityKey));
    m.put("nbf", notBefore);
    m.put("exp", notAfter);
    return Jcs.canonicalize(m);
  }

  /**
   * Signs this certificate with the mesh root identity.
   *
   * @param root the root ML-DSA-87 signing identity
   * @return this certificate, now signed
   */
  public Certificate sign(Signer root) {
    if(root.level() != Signer.Level.DSA87)
      throw new IllegalArgumentException("the mesh root must be an ML-DSA-87 identity");
    this.signature = B64ENC.encodeToString(root.sign(canonicalBytes()));
    return this;
  }

  /**
   * Verifies this certificate against a pinned root public key, mesh identity,
   * and current time.
   *
   * @param rootPublicKey the pinned raw ML-DSA-87 root public key
   * @param expectedMesh the mesh this node belongs to
   * @param nowSeconds the current time (Unix seconds)
   * @throws CertificateException if any check fails
   */
  public void verify(byte[] rootPublicKey, String expectedMesh, long nowSeconds)
      throws CertificateException {
    if(!expectedMesh.equals(mesh))
      throw new CertificateException("mesh mismatch: " + mesh + " != " + expectedMesh);
    if(nowSeconds < notBefore)
      throw new CertificateException("certificate not yet valid");
    if(nowSeconds > notAfter)
      throw new CertificateException("certificate expired");
    if(signature == null)
      throw new CertificateException("certificate is unsigned");
    boolean ok = Signer.verifier(Signer.Level.DSA87, rootPublicKey)
        .verify(canonicalBytes(), B64DEC.decode(signature));
    if(!ok)
      throw new CertificateException("root signature does not verify");
  }

  /** @return the node's raw ML-DSA-65 identity public key */
  public byte[] identityKey() {
    return identityKey.clone();
  }

  /** @return the node's display label */
  public String label() {
    return label;
  }

  /** @return the mesh identifier */
  public String mesh() {
    return mesh;
  }

  /** @return the certificate as a JSON object, including the signature */
  public JSONObject toJSON() {
    JSONObject o = new JSONObject();
    o.put("v", VERSION);
    o.put("mesh", mesh);
    o.put("label", label);
    o.put("idk", B64ENC.encodeToString(identityKey));
    o.put("nbf", notBefore);
    o.put("exp", notAfter);
    if(signature != null) o.put("sig", signature);
    return o;
  }

  /**
   * Parses a certificate from its JSON form.
   *
   * @param o the JSON object
   * @return the parsed certificate
   * @throws CertificateException if the version is unsupported
   */
  public static Certificate fromJSON(JSONObject o) throws CertificateException {
    if(o.getInt("v") != VERSION)
      throw new CertificateException("unsupported certificate version " + o.getInt("v"));
    Certificate c = new Certificate(
        o.getString("mesh"),
        o.getString("label"),
        B64DEC.decode(o.getString("idk")),
        o.getLong("nbf"),
        o.getLong("exp"));
    if(o.has("sig")) c.signature = o.getString("sig");
    return c;
  }

  /** Thrown when a certificate is malformed or fails verification. */
  public static final class CertificateException extends Exception {
    CertificateException(String message) {
      super(message);
    }
  }
}
