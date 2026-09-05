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

package com.axonibyte.bonemesh.v3.transport;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HexFormat;

import org.json.JSONObject;

/**
 * The transport-frame known-answer vector
 * (spec/corpus/transcripts/transport-frame.json): given a direction key, a
 * sequence number, and an inner plaintext, the sealed ciphertext is fixed. The
 * Go conformance runner reproduces it, proving the encrypted data channel — the
 * ability of a node in one language to read a frame sealed by another —
 * interoperates.
 *
 * <p>No argument generates and prints the vector; one path argument verifies
 * it.</p>
 *
 * @author Caleb L. Power
 */
public final class TransportDump {

  private TransportDump() { }

  private static final HexFormat HEX = HexFormat.of();

  /**
   * @param args empty to generate, or one path to verify
   * @throws Exception on I/O failure
   */
  public static void main(String[] args) throws Exception {
    if(args.length == 0) {
      System.out.println(build(fixedInputs()).toString(2));
      return;
    }
    JSONObject doc = new JSONObject(
        new String(Files.readAllBytes(Paths.get(args[0])), StandardCharsets.UTF_8));
    String want = doc.getJSONObject("outputs").getString("ct_hex");
    String got = build(doc.getJSONObject("inputs")).getJSONObject("outputs").getString("ct_hex");
    if(want.equals(got)) {
      System.out.println("PASS ct_hex");
      System.out.println("transport frame matches");
    } else {
      System.out.println("FAIL ct_hex\n  got:  " + got + "\n  want: " + want);
      System.exit(1);
    }
  }

  private static JSONObject fixedInputs() {
    byte[] key = new byte[32];
    for(int i = 0; i < 32; i++) key[i] = (byte) (i + 1);
    byte[] inner = "{\"type\":\"data\",\"line\":\"hello\"}".getBytes(StandardCharsets.UTF_8);
    return new JSONObject()
        .put("key_hex", HEX.formatHex(key))
        .put("seq", 7)
        .put("inner_plaintext_hex", HEX.formatHex(inner));
  }

  private static JSONObject build(JSONObject inputs) {
    byte[] key = HEX.parseHex(inputs.getString("key_hex"));
    long seq = inputs.getLong("seq");
    byte[] inner = HEX.parseHex(inputs.getString("inner_plaintext_hex"));
    byte[] ct = TransportSession.sealCiphertext(key, seq, inner);
    return new JSONObject()
        .put("description",
            "Transport-frame vector (protocol.md 4). ct = ChaCha20-Poly1305(key, "
            + "nonce, empty AAD, inner_plaintext), where nonce is 4 zero bytes "
            + "then the 64-bit little-endian seq. A conforming implementation "
            + "reproduces ct_hex and can open it.")
        .put("inputs", inputs)
        .put("outputs", new JSONObject().put("ct_hex", HEX.formatHex(ct)));
  }
}
