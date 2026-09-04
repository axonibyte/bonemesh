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

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Cross-language interop check: reads the shared corpus
 * (spec/corpus/canon.json) and confirms this Java canonicalizer reproduces each
 * vector's expected {@code canonical} bytes. Because the Go conformance runner
 * already validates the same file, agreement here means Java and Go produce
 * byte-identical certificate signing pre-images.
 *
 * <p>Invoked by interop/check-canon.sh. Exits non-zero on any mismatch.</p>
 *
 * @author Caleb L. Power
 */
public final class CanonDump {

  private CanonDump() { }

  /**
   * @param args a single argument: the path to canon.json
   * @throws Exception if the corpus cannot be read
   */
  public static void main(String[] args) throws Exception {
    if(args.length != 1) {
      System.err.println("usage: CanonDump <path-to-canon.json>");
      System.exit(2);
    }
    String text = new String(Files.readAllBytes(Paths.get(args[0])), StandardCharsets.UTF_8);
    JSONArray vectors = new JSONObject(text).getJSONArray("vectors");
    int failures = 0;
    for(int i = 0; i < vectors.length(); i++) {
      JSONObject v = vectors.getJSONObject(i);
      String name = v.getString("name");
      String want = v.getString("canonical");
      String got = new String(Jcs.canonicalize(toMap(v.getJSONObject("cert"))), StandardCharsets.UTF_8);
      if(got.equals(want)) {
        System.out.println("PASS " + name);
      } else {
        System.out.println("FAIL " + name + "\n  got:  " + got + "\n  want: " + want);
        failures++;
      }
    }
    if(failures > 0) {
      System.err.println(failures + " vector(s) mismatched");
      System.exit(1);
    }
    System.out.println("all " + vectors.length() + " canon vectors match");
  }

  // Convert a cert JSON object to the value map Jcs expects, dropping "sig" and
  // coercing JSON numbers to Long.
  private static Map<String, Object> toMap(JSONObject cert) {
    Map<String, Object> m = new LinkedHashMap<>();
    for(String key : cert.keySet()) {
      if(key.equals("sig")) continue;
      Object val = cert.get(key);
      if(val instanceof Number) m.put(key, ((Number) val).longValue());
      else m.put(key, val.toString());
    }
    return m;
  }
}
