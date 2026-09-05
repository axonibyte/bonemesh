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
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.json.JSONObject;

/**
 * Splits an oversized application payload across several data messages
 * (protocol.md &sect;6), all sharing one message id, so the frame size cap
 * never limits application data. The pinned encoding: the payload is serialized
 * to UTF-8 and Base64-encoded, and that string is split into {@code n} segments;
 * chunk {@code i} of {@code n} carries its segment as
 * <code>payload = {"seg": "&lt;segment&gt;"}</code> with <code>chunk = {i, n}</code>.
 * A single-segment payload is sent unchunked (the payload object directly, no
 * {@code chunk}). Reassembly is {@link Reassembler}.
 *
 * @author Caleb L. Power
 */
public final class Chunker {

  /** Maximum Base64 characters per segment (keeps a sealed frame under the cap). */
  public static final int MAX_SEGMENT_CHARS = 32000;

  private Chunker() { }

  /**
   * Splits a payload into one or more data messages.
   *
   * @param mid the shared message id
   * @param from the origin label
   * @param to the destination label
   * @param ttl the hop limit
   * @param payload the application payload
   * @return the data messages to send in order
   */
  public static List<JSONObject> split(String mid, String from, String to, int ttl, JSONObject payload) {
    String b64 = Base64.getEncoder().encodeToString(payload.toString().getBytes(StandardCharsets.UTF_8));
    List<JSONObject> out = new ArrayList<>();
    if(b64.length() <= MAX_SEGMENT_CHARS) {
      out.add(Messages.data(mid, from, to, ttl, payload)); // unchunked
      return out;
    }
    int n = (b64.length() + MAX_SEGMENT_CHARS - 1) / MAX_SEGMENT_CHARS;
    for(int i = 0; i < n; i++) {
      int start = i * MAX_SEGMENT_CHARS;
      int end = Math.min(start + MAX_SEGMENT_CHARS, b64.length());
      JSONObject seg = new JSONObject().put("seg", b64.substring(start, end));
      JSONObject msg = Messages.data(mid, from, to, ttl, seg)
          .put("chunk", new JSONObject().put("i", i).put("n", n));
      out.add(msg);
    }
    return out;
  }
}
