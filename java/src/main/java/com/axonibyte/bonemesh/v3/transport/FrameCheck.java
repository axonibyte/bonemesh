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
import java.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Cross-language interop check: reads the shared frame corpus
 * (spec/corpus/framing.json) and confirms this Java frame classifier reaches
 * the same accept/reject verdict as the Go conformance runner on every case.
 * Invoked by interop/check-framing.sh; exits non-zero on any disagreement.
 *
 * @author Caleb L. Power
 */
public final class FrameCheck {

  private FrameCheck() { }

  /**
   * @param args a single argument: the path to framing.json
   * @throws Exception if the corpus cannot be read
   */
  public static void main(String[] args) throws Exception {
    if(args.length != 1) {
      System.err.println("usage: FrameCheck <path-to-framing.json>");
      System.exit(2);
    }
    JSONObject doc = new JSONObject(
        new String(Files.readAllBytes(Paths.get(args[0])), StandardCharsets.UTF_8));
    JSONArray cases = doc.getJSONArray("cases");
    int failures = 0;
    for(int i = 0; i < cases.length(); i++) {
      JSONObject c = cases.getJSONObject(i);
      String name = c.getString("name");
      int cap = c.getString("kind").equals("handshake")
          ? FrameCodec.HANDSHAKE_CAP : FrameCodec.TRANSPORT_CAP;
      byte[] raw = Base64.getDecoder().decode(c.getString("bytes_b64"));
      FrameCodec.Verdict v = FrameCodec.classify(raw, cap);

      boolean ok;
      if(c.getString("expect").equals("accept")) {
        ok = v.accepted();
      } else {
        ok = !v.accepted() && c.getString("reason").equals(v.reason());
      }
      if(ok) {
        System.out.println("PASS " + name);
      } else {
        System.out.println("FAIL " + name + ": expect=" + c.getString("expect")
            + " reason=" + c.optString("reason") + " got="
            + (v.accepted() ? "accept" : "reject(" + v.reason() + ")"));
        failures++;
      }
    }
    if(failures > 0) {
      System.err.println(failures + " frame case(s) disagreed");
      System.exit(1);
    }
    System.out.println("all " + cases.length() + " frame cases match");
  }
}
