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
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.json.JSONObject;

/**
 * Reassembles chunked application payloads at the destination (protocol.md
 * &sect;6), the counterpart to {@link Chunker}. Feed it each inbound data
 * message; it returns the reassembled payload once the final segment of a
 * message id arrives, or empty while a message id is still incomplete. An
 * unchunked message completes immediately.
 *
 * <p>Not thread-safe; the owning node serializes access per peer.</p>
 *
 * @author Caleb L. Power
 */
public final class Reassembler {

  private final Map<String, Partial> partials = new HashMap<>();

  /**
   * Offers a data message for reassembly.
   *
   * @param dataMessage an inbound data message
   * @return the reassembled application payload when complete, else empty
   */
  public Optional<JSONObject> offer(JSONObject dataMessage) {
    JSONObject chunk = dataMessage.optJSONObject("chunk");
    if(chunk == null || chunk.getInt("n") == 1) {
      return Optional.of(dataMessage.getJSONObject("payload")); // unchunked
    }
    String mid = dataMessage.getString("mid");
    int n = chunk.getInt("n");
    int i = chunk.getInt("i");
    Partial partial = partials.computeIfAbsent(mid, k -> new Partial(n));
    if(i < 0 || i >= n || n != partial.segments.length) return Optional.empty(); // inconsistent
    partial.put(i, dataMessage.getJSONObject("payload").getString("seg"));
    if(!partial.complete()) return Optional.empty();

    partials.remove(mid);
    String b64 = String.join("", partial.segments);
    byte[] bytes = Base64.getDecoder().decode(b64);
    return Optional.of(new JSONObject(new String(bytes, StandardCharsets.UTF_8)));
  }

  private static final class Partial {
    private final String[] segments;
    private int received;

    Partial(int n) {
      this.segments = new String[n];
    }

    void put(int i, String seg) {
      if(segments[i] == null) {
        segments[i] = seg;
        received++;
      }
    }

    boolean complete() {
      return received == segments.length;
    }
  }
}
