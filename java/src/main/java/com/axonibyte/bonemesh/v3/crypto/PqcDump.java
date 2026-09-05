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
import java.security.SecureRandom;
import java.util.HexFormat;

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
 * @author Caleb L. Power
 */
public final class PqcDump {

  private PqcDump() { }

  private static final HexFormat HEX = HexFormat.of();

  /**
   * @param args ignored; prints the vector JSON
   */
  public static void main(String[] args) {
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
}
