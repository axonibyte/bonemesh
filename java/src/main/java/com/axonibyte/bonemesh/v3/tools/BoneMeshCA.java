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

package com.axonibyte.bonemesh.v3.tools;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.json.JSONObject;

import com.axonibyte.bonemesh.v3.cert.Certificate;
import com.axonibyte.bonemesh.v3.crypto.Signer;

/**
 * The mesh certificate authority tool (security.md &sect;9). It generates a
 * mesh root keypair offline, generates node identity keypairs, issues
 * membership certificates by signing a node's identity with the root, and
 * verifies certificates against a pinned root public key. The root private key
 * is written once and never belongs on a node.
 *
 * <p>The static methods carry the logic and are directly testable; {@link
 * #main(String[])} is the file-based CLI.</p>
 *
 * @author Caleb L. Power
 */
public final class BoneMeshCA {

  private static final Base64.Encoder B64ENC = Base64.getEncoder();
  private static final Base64.Decoder B64DEC = Base64.getDecoder();
  private static final SecureRandom RNG = new SecureRandom();

  private BoneMeshCA() { }

  /**
   * Generates a mesh root ML-DSA-87 signing identity.
   *
   * @return the root identity (holding the private key)
   */
  public static Signer generateRoot() {
    return Signer.generate(Signer.Level.DSA87, RNG);
  }

  /**
   * Generates a node ML-DSA-65 identity.
   *
   * @return the node identity (holding the private key)
   */
  public static Signer generateIdentity() {
    return Signer.generate(Signer.Level.DSA65, RNG);
  }

  /**
   * Issues a membership certificate.
   *
   * @param root the mesh root identity
   * @param mesh the mesh identifier
   * @param label the node's label
   * @param nodePublicKey the node's raw ML-DSA-65 public key
   * @param notBefore validity start (Unix seconds)
   * @param notAfter validity end (Unix seconds)
   * @return the signed certificate
   */
  public static Certificate issue(Signer root, String mesh, String label,
      byte[] nodePublicKey, long notBefore, long notAfter) {
    return new Certificate(mesh, label, nodePublicKey, notBefore, notAfter).sign(root);
  }

  /**
   * @param args the CLI arguments
   * @throws Exception on I/O or verification failure
   */
  public static void main(String[] args) throws Exception {
    if(args.length < 1) {
      usage();
      System.exit(2);
    }
    switch(args[0]) {
      case "init-root":   initRoot(flags(args));   break;
      case "keygen":      keygen(flags(args));      break;
      case "issue":       issueCli(flags(args));    break;
      case "verify":      verifyCli(flags(args));   break;
      default:
        usage();
        System.exit(2);
    }
  }

  private static void initRoot(Map<String, String> f) throws IOException {
    Path dir = Paths.get(require(f, "out"));
    Files.createDirectories(dir);
    Signer root = generateRoot();
    writeKey(dir.resolve("root.priv"), root.privateKey());
    writeKey(dir.resolve("root.pub"), root.publicKey());
    System.out.println("root keypair written to " + dir + " (guard root.priv; it never goes on a node)");
  }

  private static void keygen(Map<String, String> f) throws IOException {
    String prefix = require(f, "out");
    Signer id = generateIdentity();
    writeKey(Paths.get(prefix + ".priv"), id.privateKey());
    writeKey(Paths.get(prefix + ".pub"), id.publicKey());
    System.out.println("identity keypair written to " + prefix + ".{priv,pub}");
  }

  private static void issueCli(Map<String, String> f) throws IOException {
    Signer root = Signer.fromKeys(Signer.Level.DSA87,
        readKey(Paths.get(require(f, "root-pub"))),
        readKey(Paths.get(require(f, "root-priv"))));
    byte[] nodePub = readKey(Paths.get(require(f, "key")));
    long now = System.currentTimeMillis() / 1000L;
    long days = Long.parseLong(f.getOrDefault("days", "30"));
    Certificate cert = issue(root, require(f, "mesh"), require(f, "label"),
        nodePub, now, now + days * 86400L);
    Path out = Paths.get(f.getOrDefault("out", require(f, "label") + ".cert.json"));
    Files.write(out, cert.toJSON().toString(2).getBytes(StandardCharsets.UTF_8));
    System.out.println("certificate for " + require(f, "label") + " written to " + out);
  }

  private static void verifyCli(Map<String, String> f) throws Exception {
    byte[] rootPub = readKey(Paths.get(require(f, "root-pub")));
    Certificate cert = Certificate.fromJSON(new JSONObject(
        new String(Files.readAllBytes(Paths.get(require(f, "cert"))), StandardCharsets.UTF_8)));
    long now = System.currentTimeMillis() / 1000L;
    try {
      cert.verify(rootPub, require(f, "mesh"), now);
      System.out.println("OK: certificate for " + cert.label() + " verifies");
    } catch(Certificate.CertificateException e) {
      System.out.println("INVALID: " + e.getMessage());
      System.exit(1);
    }
  }

  private static void writeKey(Path path, byte[] key) throws IOException {
    Files.write(path, B64ENC.encodeToString(key).getBytes(StandardCharsets.US_ASCII));
  }

  private static byte[] readKey(Path path) throws IOException {
    return B64DEC.decode(new String(Files.readAllBytes(path), StandardCharsets.US_ASCII).trim());
  }

  private static Map<String, String> flags(String[] args) {
    Map<String, String> f = new HashMap<>();
    for(int i = 1; i + 1 < args.length; i += 2) {
      if(args[i].startsWith("--")) f.put(args[i].substring(2), args[i + 1]);
    }
    return f;
  }

  private static String require(Map<String, String> f, String key) {
    String v = f.get(key);
    if(v == null) throw new IllegalArgumentException("missing required --" + key);
    return v;
  }

  private static void usage() {
    System.err.println("usage: bonemesh-ca <command> [--flag value ...]");
    System.err.println("  init-root --out <dir>");
    System.err.println("  keygen    --out <prefix>");
    System.err.println("  issue     --root-priv <f> --root-pub <f> --mesh <id> --label <l> --key <node.pub> [--days 30] [--out <f>]");
    System.err.println("  verify    --root-pub <f> --mesh <id> --cert <f>");
  }
}
