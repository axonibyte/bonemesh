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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HexFormat;

import org.json.JSONObject;

/**
 * The shared key-schedule known-answer vector
 * (spec/corpus/transcripts/keyschedule.json), in two modes:
 *
 * <ul>
 *   <li>no arguments: generate the vector from fixed inputs and print it;</li>
 *   <li>one argument (a path): read that vector, recompute its outputs from its
 *       inputs, and confirm they match — the Java side of the cross-language
 *       check, run on the driver where the corpus is present.</li>
 * </ul>
 *
 * The Go conformance runner performs the equivalent reproduction in its own
 * tenant; together they freeze the key-schedule constants.
 *
 * @author Caleb L. Power
 */
public final class KsDump {

  private KsDump() { }

  private static final HexFormat HEX = HexFormat.of();

  /**
   * @param args empty to generate, or one path to verify
   * @throws Exception on I/O or AEAD failure
   */
  public static void main(String[] args) throws Exception {
    if(args.length == 0) {
      System.out.println(generate(fixedInputs()).toString(2));
    } else if(args.length == 1) {
      JSONObject doc = new JSONObject(
          new String(Files.readAllBytes(Paths.get(args[0])), StandardCharsets.UTF_8));
      JSONObject recomputed = generate(doc.getJSONObject("inputs")).getJSONObject("outputs");
      JSONObject expected = doc.getJSONObject("outputs");
      int mismatches = 0;
      for(String k : expected.keySet()) {
        String want = expected.getString(k);
        String got = recomputed.optString(k);
        if(want.equals(got)) {
          System.out.println("PASS " + k);
        } else {
          System.out.println("FAIL " + k + "\n  got:  " + got + "\n  want: " + want);
          mismatches++;
        }
      }
      if(mismatches > 0) {
        System.err.println(mismatches + " key-schedule output(s) mismatched");
        System.exit(1);
      }
      System.out.println("all key-schedule outputs match");
    } else {
      System.err.println("usage: KsDump [path-to-keyschedule.json]");
      System.exit(2);
    }
  }

  private static JSONObject fixedInputs() {
    return new JSONObject()
        .put("protocol_name", SymmetricState.PROTOCOL_NAME)
        .put("mesh_hex", HEX.formatHex("acme-prod".getBytes(StandardCharsets.UTF_8)))
        .put("ss_dh_hex", HEX.formatHex(ramp(1)))
        .put("ss_kem_hex", HEX.formatHex(ramp(0x21)))
        .put("plaintext1_hex", HEX.formatHex("responder-auth".getBytes(StandardCharsets.UTF_8)))
        .put("plaintext2_hex", HEX.formatHex("initiator-auth".getBytes(StandardCharsets.UTF_8)));
  }

  private static JSONObject generate(JSONObject inputs) throws Exception {
    byte[] mesh = HEX.parseHex(inputs.getString("mesh_hex"));
    byte[] ssDh = HEX.parseHex(inputs.getString("ss_dh_hex"));
    byte[] ssKem = HEX.parseHex(inputs.getString("ss_kem_hex"));
    byte[] pt1 = HEX.parseHex(inputs.getString("plaintext1_hex"));
    byte[] pt2 = HEX.parseHex(inputs.getString("plaintext2_hex"));

    SymmetricState s = new SymmetricState();
    String hInit = HEX.formatHex(s.transcriptHash());
    s.mixHash(mesh);
    String hAfterMesh = HEX.formatHex(s.transcriptHash());
    s.mixKey(ssDh);
    String ckAfterDh = HEX.formatHex(s.chainingKey());
    s.mixKey(ssKem);
    String ckAfterKem = HEX.formatHex(s.chainingKey());
    byte[] ct1 = s.encryptAndHash(pt1);
    String hAfterCt1 = HEX.formatHex(s.transcriptHash());
    byte[] ct2 = s.encryptAndHash(pt2);
    String hAfterCt2 = HEX.formatHex(s.transcriptHash());
    byte[][] tk = s.split();

    JSONObject outputs = new JSONObject()
        .put("h_init", hInit)
        .put("h_after_mesh", hAfterMesh)
        .put("ck_after_dh", ckAfterDh)
        .put("ck_after_kem", ckAfterKem)
        .put("ct1_hex", HEX.formatHex(ct1))
        .put("h_after_ct1", hAfterCt1)
        .put("ct2_hex", HEX.formatHex(ct2))
        .put("h_after_ct2", hAfterCt2)
        .put("transport_key_i2r", HEX.formatHex(tk[0]))
        .put("transport_key_r2i", HEX.formatHex(tk[1]));

    return new JSONObject()
        .put("description",
            "Key-schedule known-answer vector (security.md 5). A conforming "
            + "SymmetricState, fed 'inputs', must reproduce every value in "
            + "'outputs'. Sequence: init(protocol_name); mixHash(mesh); "
            + "mixKey(ss_dh); mixKey(ss_kem); ct1=encryptAndHash(plaintext1); "
            + "ct2=encryptAndHash(plaintext2); split().")
        .put("inputs", inputs)
        .put("outputs", outputs);
  }

  private static byte[] ramp(int start) {
    byte[] b = new byte[32];
    for(int i = 0; i < 32; i++) b[i] = (byte) (start + i);
    return b;
  }
}
