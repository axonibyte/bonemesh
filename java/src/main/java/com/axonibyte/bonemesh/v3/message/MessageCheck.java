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

package com.axonibyte.bonemesh.v3.message;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Cross-language interop check: reads the shared message corpus
 * (spec/corpus/messages.json) and confirms this Java validator reaches the same
 * valid/invalid verdict — and the same reason tag — as the Go conformance
 * runner on every case. Invoked by interop/check-messages.sh; exits non-zero on
 * any disagreement.
 *
 * @author Caleb L. Power
 */
public final class MessageCheck {

  private MessageCheck() { }

  /**
   * @param args a single argument: the path to messages.json
   * @throws Exception if the corpus cannot be read
   */
  public static void main(String[] args) throws Exception {
    if(args.length != 1) {
      System.err.println("usage: MessageCheck <path-to-messages.json>");
      System.exit(2);
    }
    JSONObject doc = new JSONObject(
        new String(Files.readAllBytes(Paths.get(args[0])), StandardCharsets.UTF_8));
    JSONArray cases = doc.getJSONArray("cases");
    int failures = 0;
    for(int i = 0; i < cases.length(); i++) {
      JSONObject c = cases.getJSONObject(i);
      String name = c.getString("name");
      String reason = MessageSchema.validate(c.getString("schema"), c.getJSONObject("frame"));
      boolean valid = reason == null;

      boolean ok;
      if(c.getString("expect").equals("valid")) {
        ok = valid;
      } else {
        ok = !valid && c.getString("reason").equals(reason);
      }
      if(ok) {
        System.out.println("PASS " + name);
      } else {
        System.out.println("FAIL " + name + ": expect=" + c.getString("expect")
            + " reason=" + c.optString("reason")
            + " got=" + (valid ? "valid" : "invalid(" + reason + ")"));
        failures++;
      }
    }
    if(failures > 0) {
      System.err.println(failures + " message case(s) disagreed");
      System.exit(1);
    }
    System.out.println("all " + cases.length() + " message cases match");
  }
}
