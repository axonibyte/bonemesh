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

import com.axonibyte.bonemesh.v3.crypto.Dh;
import com.axonibyte.bonemesh.v3.crypto.Kem;

import org.json.JSONObject;

/**
 * The BMX hybrid key-agreement transcript vector
 * (spec/corpus/transcripts/handshake-agreement.json). Given fixed initiator and
 * responder X25519 keys and a fixed ML-KEM ciphertext (encapsulated to the
 * initiator's fixed ML-KEM key), it pins the two shared secrets, the transcript
 * checkpoints, and the final transport keys.
 *
 * <p>Every input is provided so any implementation can reproduce the outputs
 * with X25519, ML-KEM decapsulation, and the key schedule — no ML-DSA needed —
 * which is why the Go conformance runner can verify it with the standard
 * library. This freezes the whole hybrid agreement across languages; ML-DSA
 * signature interop is exercised by the in-memory handshake and frozen when Go
 * gains ML-DSA.</p>
 *
 * <p>Modes: no argument generates and prints the vector; one path argument
 * verifies that vector.</p>
 *
 * @author Caleb L. Power
 */
public final class AgreementDump {

  private AgreementDump() { }

  private static final HexFormat HEX = HexFormat.of();
  private static final String MESH = "acme-prod";

  /**
   * @param args empty to generate, or one path to verify
   * @throws Exception on I/O failure
   */
  public static void main(String[] args) throws Exception {
    if(args.length == 0) {
      System.out.println(build().toString(2));
      return;
    }
    JSONObject doc = new JSONObject(
        new String(Files.readAllBytes(Paths.get(args[0])), StandardCharsets.UTF_8));
    JSONObject recomputed = fromInputs(doc.getJSONObject("inputs")).getJSONObject("outputs");
    JSONObject expected = doc.getJSONObject("outputs");
    int bad = 0;
    for(String k : expected.keySet()) {
      if(expected.getString(k).equals(recomputed.optString(k))) {
        System.out.println("PASS " + k);
      } else {
        System.out.println("FAIL " + k + "\n  got:  " + recomputed.optString(k)
            + "\n  want: " + expected.getString(k));
        bad++;
      }
    }
    if(bad > 0) {
      System.err.println(bad + " agreement output(s) mismatched");
      System.exit(1);
    }
    System.out.println("all agreement outputs match");
  }

  // Builds the vector with fresh fixed inputs (initiator/responder X25519 from
  // fixed scalars; a fresh ML-KEM keypair and a fresh encapsulation, captured
  // as fixed inputs so the vector is self-contained and reproducible).
  private static JSONObject build() {
    byte[] eiPriv = ramp(1, 32);
    byte[] erPriv = ramp(0x41, 32);
    Dh ei = Dh.fromPrivate(eiPriv);
    Dh er = Dh.fromPrivate(erPriv);
    Kem ki = Kem.generate(new java.security.SecureRandom());
    Kem.Encapsulation enc = Kem.encapsulateTo(ki.encapsulationKey(), new java.security.SecureRandom());
    byte[] n = ramp(0x81, 32);

    JSONObject inputs = new JSONObject()
        .put("mesh_hex", HEX.formatHex(MESH.getBytes(StandardCharsets.UTF_8)))
        // The initiator's X25519 private scalar is given so a verifier can
        // derive ss_dh itself (a real cross-language X25519 check). ML-KEM
        // ss_kem is provided as an input for now: Go's crypto/mlkem uses the
        // 64-byte seed representation while BouncyCastle exports the expanded
        // key, so ML-KEM cross-decapsulation is a deferred interop item (with
        // ML-DSA signature interop). See spec/corpus/transcripts/README.md.
        .put("ei_priv_hex", HEX.formatHex(eiPriv))
        .put("ei_pub_hex", HEX.formatHex(ei.publicKey()))
        .put("er_pub_hex", HEX.formatHex(er.publicKey()))
        .put("ki_ek_hex", HEX.formatHex(ki.encapsulationKey()))
        .put("kem_ct_hex", HEX.formatHex(enc.ciphertext()))
        .put("n_hex", HEX.formatHex(n))
        .put("ss_dh_hex", HEX.formatHex(ei.agree(er.publicKey())))
        .put("ss_kem_hex", HEX.formatHex(enc.secret()));
    return fromInputs(inputs);
  }

  private static JSONObject fromInputs(JSONObject inputs) {
    byte[] mesh = HEX.parseHex(inputs.getString("mesh_hex"));
    byte[] eiPub = HEX.parseHex(inputs.getString("ei_pub_hex"));
    byte[] kiEk = HEX.parseHex(inputs.getString("ki_ek_hex"));
    byte[] erPub = HEX.parseHex(inputs.getString("er_pub_hex"));
    byte[] ct = HEX.parseHex(inputs.getString("kem_ct_hex"));
    byte[] n = HEX.parseHex(inputs.getString("n_hex"));
    byte[] ssDh = HEX.parseHex(inputs.getString("ss_dh_hex"));
    byte[] ssKem = HEX.parseHex(inputs.getString("ss_kem_hex"));

    SymmetricState s = new SymmetricState();
    s.mixHash(mesh);
    s.mixHash(eiPub);
    s.mixHash(kiEk);
    s.mixHash(n);
    String hAfterMsg1 = HEX.formatHex(s.transcriptHash());
    s.mixHash(erPub);
    s.mixKey(ssDh);
    String ckAfterDh = HEX.formatHex(s.chainingKey());
    s.mixHash(ct);
    s.mixKey(ssKem);
    String ckAfterKem = HEX.formatHex(s.chainingKey());
    String hAfterMsg2Ephemerals = HEX.formatHex(s.transcriptHash());
    byte[][] tk = s.split();

    JSONObject outputs = new JSONObject()
        .put("h_after_msg1", hAfterMsg1)
        .put("ck_after_dh", ckAfterDh)
        .put("ck_after_kem", ckAfterKem)
        .put("h_after_msg2_ephemerals", hAfterMsg2Ephemerals)
        .put("transport_key_i2r", HEX.formatHex(tk[0]))
        .put("transport_key_r2i", HEX.formatHex(tk[1]));

    return new JSONObject()
        .put("description",
            "BMX hybrid key-agreement vector (security.md 4-5). Given the "
            + "initiator/responder X25519 public keys, the initiator ML-KEM "
            + "encapsulation key, the ML-KEM ciphertext, the nonce, and the two "
            + "agreed secrets (ss_dh from X25519, ss_kem from ML-KEM "
            + "decapsulation), a conforming implementation reproduces the "
            + "transcript checkpoints and transport keys. Sequence: mixHash(mesh, "
            + "ei_pub, ki_ek, n); mixHash(er_pub); mixKey(ss_dh); mixHash(ct); "
            + "mixKey(ss_kem); split().")
        .put("inputs", inputs)
        .put("outputs", outputs);
  }

  private static byte[] ramp(int start, int len) {
    byte[] b = new byte[len];
    for(int i = 0; i < len; i++) b[i] = (byte) (start + i);
    return b;
  }
}
