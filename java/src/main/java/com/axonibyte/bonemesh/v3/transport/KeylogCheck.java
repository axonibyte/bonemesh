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
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Reads the shared key-log vector (spec/corpus/keylog.json) and confirms this
 * implementation can open a key-logged capture.
 *
 * <p>security.md §8 pins one implementation-neutral key-log format precisely so
 * that a single inspector reads a log written by a node in any language. That
 * claim needs agreement in <em>both</em> directions: emitting lines your own
 * reader accepts is not enough. This checks the reading half against the
 * committed capture. The writing half is covered by each port's own key-log
 * tests and, live and cross-language, by interop tier 10.</p>
 *
 * <p>Invoked by interop/check-keylog.sh.</p>
 *
 * @author Caleb L. Power
 */
public final class KeylogCheck {

  private KeylogCheck() { }

  private static final HexFormat HEX = HexFormat.of();
  private static final Pattern LABEL = Pattern.compile("^BMX3_(I2R|R2I)_TRAFFIC_(\\d+)$");

  /**
   * @param args one path, to keylog.json
   * @throws Exception on I/O failure
   */
  public static void main(String[] args) throws Exception {
    if(args.length != 1) {
      System.err.println("usage: KeylogCheck <keylog.json>");
      System.exit(2);
    }
    JSONObject doc = new JSONObject(
        new String(Files.readAllBytes(Paths.get(args[0])), StandardCharsets.UTF_8));
    JSONArray capture = doc.optJSONArray("capture");
    JSONArray expected = doc.optJSONArray("expected");
    if(capture == null || expected == null || capture.length() == 0
        || capture.length() != expected.length()) {
      System.err.println("vector malformed");
      System.exit(1);
    }

    Map<String, byte[]> keys = parseKeylog(doc.optJSONArray("keylog"));
    if(keys.isEmpty()) {
      System.err.println("no usable key-log entries in the vector");
      System.exit(1);
    }

    int failures = 0;
    for(int i = 0; i < capture.length(); i++) {
      JSONObject frame = capture.getJSONObject(i);
      JSONObject want = expected.getJSONObject(i);
      String dir = frame.getString("dir");
      long seq = frame.getJSONObject("frame").getLong("seq");
      byte[] ct = Base64.getDecoder().decode(frame.getJSONObject("frame").getString("ct"));
      byte[] key = keys.get(dir + ":" + want.getInt("epoch"));
      if(key == null) {
        System.out.printf("FAIL frame %d: no key for %s epoch %d%n", i, dir, want.getInt("epoch"));
        failures++;
        continue;
      }
      byte[] pt;
      try {
        pt = TransportSession.openCiphertext(key, seq, ct);
      } catch(Exception e) {
        System.out.printf("FAIL frame %d: the logged %s key did not open it%n", i, dir);
        failures++;
        continue;
      }
      // JSONObject.similar compares structurally, so member order does not
      // matter -- the contract is the structure, not the text.
      JSONObject got = new JSONObject(new String(pt, StandardCharsets.UTF_8));
      if(got.similar(want.getJSONObject("inner"))) {
        System.out.printf("PASS frame %d (%s seq %d)%n", i, dir, seq);
      } else {
        System.out.printf("FAIL frame %d%n  got:  %s%n  want: %s%n",
            i, got, want.getJSONObject("inner"));
        failures++;
      }
    }

    // Self-test the oracle: a ciphertext no key seals must be refused, or a
    // checker that reported success for everything would look identical to this.
    byte[] anyKey = keys.values().iterator().next();
    boolean refused = false;
    try {
      TransportSession.openCiphertext(anyKey, 0L, new byte[32]);
    } catch(Exception e) {
      refused = true;
    }
    if(refused) System.out.println("PASS self-test: an unopenable frame is refused");
    else {
      System.out.println("FAIL self-test: an unopenable frame was accepted");
      failures++;
    }

    if(failures > 0) {
      System.err.println(failures + " key-log frame(s) failed");
      System.exit(1);
    }
    System.out.println("every captured frame opens with its logged key and reproduces the vector");
  }

  // '#' lines are comments; an unknown label shape is ignored rather than fatal,
  // so a future label is not a breaking change.
  private static Map<String, byte[]> parseKeylog(JSONArray lines) {
    Map<String, byte[]> keys = new HashMap<>();
    if(lines == null) return keys;
    for(int i = 0; i < lines.length(); i++) {
      String line = lines.getString(i).trim();
      if(line.isEmpty() || line.startsWith("#")) continue;
      String[] parts = line.split("\\s+");
      if(parts.length != 3) continue;
      Matcher m = LABEL.matcher(parts[0]);
      if(!m.matches()) continue;
      byte[] key;
      try {
        key = HEX.parseHex(parts[2]);
      } catch(IllegalArgumentException e) {
        continue;
      }
      if(key.length != 32) continue;
      keys.put(m.group(1).toLowerCase() + ":" + m.group(2), key);
    }
    return keys;
  }
}
