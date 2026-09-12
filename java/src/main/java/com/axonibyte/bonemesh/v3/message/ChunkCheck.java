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
import java.util.ArrayList;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Cross-language splitting check: reads the shared corpus
 * (spec/corpus/chunk.json) and confirms two things.
 *
 * <p>First, the pinned &sect;0 constants match this implementation's — including
 * the three (chunk count, in-flight count, reassembly timeout) that
 * {@code specsrc} deliberately does not check, because a substring search for
 * 1024, 256 or 30000 is satisfied by any buffer size already in the tree.</p>
 *
 * <p>Second, and this is the part nothing else in the repository can see: the
 * segments this implementation produces land on exactly the byte boundaries the
 * corpus pins. That is how all seven are shown to cut in the <em>same</em> places
 * rather than merely to cut.</p>
 *
 * <p>Invoked by interop/check-chunk.sh; exits non-zero on any disagreement.</p>
 *
 * @author Caleb L. Power
 */
public final class ChunkCheck {

  private ChunkCheck() { }

  /**
   * @param args a single argument: the path to chunk.json
   * @throws Exception if the corpus cannot be read
   */
  public static void main(String[] args) throws Exception {
    if(args.length != 1) {
      System.err.println("usage: ChunkCheck <path-to-chunk.json>");
      System.exit(2);
    }
    JSONObject doc = new JSONObject(
        new String(Files.readAllBytes(Paths.get(args[0])), StandardCharsets.UTF_8));
    int failures = 0;

    JSONObject mine = new JSONObject()
        .put("max_segment_bytes", Chunker.MAX_SEGMENT_BYTES)
        .put("max_chunks", Chunker.MAX_CHUNKS)
        .put("max_reassembly_buffer", Chunker.MAX_REASSEMBLY_BUFFER)
        .put("max_concurrent_reassemblies", Chunker.MAX_CONCURRENT_REASSEMBLIES)
        .put("reassembly_timeout_millis", Reassembler.TIMEOUT_MILLIS);

    JSONObject pinned = doc.optJSONObject("constants");
    if(pinned == null || pinned.isEmpty()) {
      System.err.println("corpus declares no chunk constants");
      System.exit(1);
    }
    for(String name : pinned.keySet()) {
      long want = pinned.getLong(name);
      boolean known = mine.has(name);
      boolean ok = known && mine.getLong(name) == want;
      if(ok) {
        System.out.println("PASS constant " + name);
      } else {
        System.out.println("FAIL constant " + name
            + "  (have " + (known ? mine.getLong(name) : "nothing") + ", corpus pins " + want + ")");
        failures++;
      }
    }

    JSONArray cases = doc.optJSONArray("split_cases");
    if(cases == null || cases.isEmpty()) {
      System.err.println("corpus has no split cases");
      System.exit(1);
    }
    String mid = doc.getString("mid");
    for(int i = 0; i < cases.length(); i++) {
      JSONObject c = cases.getJSONObject(i);
      String name = c.getString("name");
      JSONObject payload = new JSONObject()
          .put(c.getString("key"), c.getString("unit").repeat(c.getInt("times")));

      List<JSONObject> msgs;
      try {
        msgs = Chunker.split(mid, "a", "b", 16, payload);
      } catch(IllegalArgumentException e) {
        System.out.println("FAIL " + name + "  (split: " + e.getMessage() + ")");
        failures++;
        continue;
      }
      boolean whole = msgs.size() == 1 && msgs.get(0).has("payload");
      List<Integer> lengths = new ArrayList<>();
      if(!whole)
        for(JSONObject m : msgs)
          lengths.add(m.getString("seg").getBytes(StandardCharsets.UTF_8).length);

      JSONArray wantArr = c.getJSONArray("segment_byte_lengths");
      List<Integer> want = new ArrayList<>();
      for(int k = 0; k < wantArr.length(); k++) want.add(wantArr.getInt(k));

      boolean ok = whole == c.getBoolean("expect_whole") && lengths.equals(want);
      String detail = ok ? ""
          : "  (whole=" + whole + " want " + c.getBoolean("expect_whole")
            + "; lengths=" + lengths + " want " + want + ")";

      // A round-trip as the second oracle: matching lengths would not catch segments
      // that are the right size and the wrong bytes.
      if(ok && !whole) {
        StringBuilder joined = new StringBuilder();
        for(JSONObject m : msgs) joined.append(m.getString("seg"));
        if(!new JSONObject(joined.toString()).toString().equals(payload.toString())) {
          ok = false;
          detail = "  (segments did not rebuild the payload)";
        }
      }
      if(ok) {
        System.out.println("PASS " + name);
      } else {
        System.out.println("FAIL " + name + detail);
        failures++;
      }
    }

    if(failures > 0) {
      System.err.println(failures + " chunk case(s) disagreed");
      System.exit(1);
    }
    System.out.println("splitting agrees with every pinned constant and cut position");
  }
}
