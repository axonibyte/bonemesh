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

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.json.JSONObject;

/**
 * Generates the post-quantum cross-language interop vector
 * (spec/corpus/transcripts/pqc-interop.json): a Java-produced ML-DSA-65
 * signature that another implementation must verify, and a Java ML-KEM-768
 * key pair with a ciphertext that another implementation must decapsulate to
 * the given shared secret. This is the concrete, regression-guarded proof that
 * the deferred post-quantum interop works — verified from the Elixir side by
 * interop/check-pqc-elixir.sh.
 *
 * <p>No argument regenerates and prints a fresh vector; one path argument
 * <em>verifies</em> the committed one, which is what interop/check-pqc.sh runs.
 * Java is the vector's producer, so verifying it here is not circular in the way
 * it may look: the vector is a frozen artifact in the repository, and this pass
 * is what notices a BouncyCastle upgrade that changes an encoding or breaks a
 * primitive underneath the committed bytes.</p>
 *
 * <p>Java is also the only implementation that can check <em>both</em> halves.
 * The vector ships the 2400-byte FIPS expanded ML-KEM decapsulation key that
 * BouncyCastle produced; Go, JS, PHP, Rust and Python are keyed by the 64-byte
 * seed and so verify the signature half only, naming the boundary explicitly
 * (see interop/check-pqc-js.sh and its peers).</p>
 *
 * @author Caleb L. Power
 */
public final class PqcDump {

  private PqcDump() { }

  private static final HexFormat HEX = HexFormat.of();

  /**
   * @param args ignored; prints the vector JSON
   */
  public static void main(String[] args) throws Exception {
    if(args.length == 1) {
      verify(args[0]);
      return;
    }
    SecureRandom rng = new SecureRandom();

    Signer id = Signer.generate(Signer.Level.DSA65, rng);
    byte[] msg = "bonemesh pqc interop".getBytes(StandardCharsets.UTF_8);
    byte[] sig = id.sign(msg);

    Kem kem = Kem.generate(rng);
    Kem.Encapsulation enc = Kem.encapsulateTo(kem.encapsulationKey(), rng);

    JSONObject mldsa = new JSONObject()
        .put("public_hex", HEX.formatHex(id.publicKey()))
        .put("message_hex", HEX.formatHex(msg))
        .put("signature_hex", HEX.formatHex(sig));

    JSONObject mlkem = new JSONObject()
        .put("decapsulation_key_hex", HEX.formatHex(kem.decapsulationKey()))
        .put("ciphertext_hex", HEX.formatHex(enc.ciphertext()))
        .put("shared_secret_hex", HEX.formatHex(enc.secret()));

    JSONObject doc = new JSONObject()
        .put("description",
            "Post-quantum cross-language interop vector, produced by the Java "
            + "reference (BouncyCastle). Another implementation must (a) verify "
            + "the ML-DSA-65 signature over message with public, and (b) "
            + "decapsulate the ML-KEM-768 ciphertext with decapsulation_key to "
            + "recover shared_secret. Success proves post-quantum interop.")
        .put("mldsa65", mldsa)
        .put("mlkem768", mlkem);

    System.out.println(doc.toString(2));
  }

  // Verifies the committed vector: the ML-DSA-65 signature through the node's
  // real verify path, and the ML-KEM-768 ciphertext by rebuilding the expanded
  // decapsulation key. The rebuild lives here rather than on Kem because a node
  // never receives a decapsulation key -- only encapsulation keys, ciphertexts
  // and public artifacts cross a boundary -- so the shipped API has no business
  // growing a loader for one.
  private static void verify(String path) throws Exception {
    JSONObject doc = new JSONObject(
        new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8));
    int failures = 0;

    JSONObject dsa = doc.getJSONObject("mldsa65");
    boolean sigOk = Signer
        .verifier(Signer.Level.DSA65, HEX.parseHex(dsa.getString("public_hex")))
        .verify(HEX.parseHex(dsa.getString("message_hex")),
            HEX.parseHex(dsa.getString("signature_hex")));
    if(sigOk) System.out.println("PASS mldsa65 signature");
    else {
      System.out.println("FAIL mldsa65 signature");
      failures++;
    }

    JSONObject kem = doc.getJSONObject("mlkem768");
    byte[] want = HEX.parseHex(kem.getString("shared_secret_hex"));
    byte[] got = new MLKEMExtractor(new MLKEMPrivateKeyParameters(
            MLKEMParameters.ml_kem_768, HEX.parseHex(kem.getString("decapsulation_key_hex"))))
        .extractSecret(HEX.parseHex(kem.getString("ciphertext_hex")));
    if(Arrays.equals(want, got)) System.out.println("PASS mlkem768 shared secret");
    else {
      System.out.println("FAIL mlkem768 shared secret\n  got:  " + HEX.formatHex(got)
          + "\n  want: " + HEX.formatHex(want));
      failures++;
    }

    if(failures > 0) {
      System.err.println(failures + " post-quantum check(s) failed");
      System.exit(1);
    }
    System.out.println("Java reproduces both halves of the shared post-quantum vector");
  }
}
