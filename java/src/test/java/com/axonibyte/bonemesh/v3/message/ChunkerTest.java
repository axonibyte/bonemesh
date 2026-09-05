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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Optional;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;

/**
 * Chunking and reassembly tests: a small payload passes through unchunked; a
 * large one splits and rebuilds byte-identically; each chunk still passes the
 * data schema; and reassembly completes only on the final segment.
 */
public class ChunkerTest {

  private static String big(int chars) {
    StringBuilder sb = new StringBuilder(chars);
    for(int i = 0; i < chars; i++) sb.append((char) ('a' + (i % 26)));
    return sb.toString();
  }

  @Test void smallPayloadIsUnchunked() {
    JSONObject payload = new JSONObject().put("line", "hello");
    List<JSONObject> msgs = Chunker.split("0".repeat(32), "a", "b", 16, payload);
    assertEquals(1, msgs.size());
    assertFalse(msgs.get(0).has("chunk"));
    assertEquals(payload.toString(), msgs.get(0).getJSONObject("payload").toString());
  }

  @Test void largePayloadSplitsAndReassembles() {
    JSONObject payload = new JSONObject().put("blob", big(120_000));
    List<JSONObject> msgs = Chunker.split("0".repeat(32), "a", "b", 16, payload);
    assertTrue(msgs.size() > 1, "large payload was not chunked");

    // Every chunk is a valid data message with matching chunk metadata.
    int n = msgs.size();
    for(int i = 0; i < n; i++) {
      JSONObject m = msgs.get(i);
      assertNull(MessageSchema.validate("data", m), "chunk failed schema: " + m);
      assertEquals(n, m.getJSONObject("chunk").getInt("n"));
      assertEquals(i, m.getJSONObject("chunk").getInt("i"));
    }

    // Reassembly returns the payload only after the last segment.
    Reassembler r = new Reassembler();
    for(int i = 0; i < n - 1; i++) assertTrue(r.offer(msgs.get(i)).isEmpty());
    Optional<JSONObject> done = r.offer(msgs.get(n - 1));
    assertTrue(done.isPresent());
    assertEquals(payload.toString(), done.get().toString());
  }

  @Test void outOfOrderChunksStillReassemble() {
    JSONObject payload = new JSONObject().put("blob", big(120_000));
    List<JSONObject> msgs = Chunker.split("0".repeat(32), "a", "b", 16, payload);
    Reassembler r = new Reassembler();
    // Offer in reverse order.
    Optional<JSONObject> done = Optional.empty();
    for(int i = msgs.size() - 1; i >= 0; i--) done = r.offer(msgs.get(i));
    assertTrue(done.isPresent());
    assertEquals(payload.toString(), done.get().toString());
  }
}
