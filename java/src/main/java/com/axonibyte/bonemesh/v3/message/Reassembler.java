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
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import org.json.JSONObject;

/**
 * Reassembles split application payloads at the destination (protocol.md
 * &sect;6.1), the counterpart to {@link Chunker}. Feed it each inbound data
 * message; it returns the payload once the final segment of a message id
 * arrives, or empty while that id is still incomplete. A whole message
 * completes immediately.
 *
 * <p>Every bound &sect;0 pins is enforced here, and enforced <em>before</em> any
 * allocation keyed on a number the peer chose. That ordering is the whole point:
 * the first version of this class called {@code computeIfAbsent} with the peer's
 * {@code n} and validated afterwards, so one frame claiming two billion segments
 * raised {@code OutOfMemoryError} at {@code -Xmx64m} — defect D7 (unbounded
 * reads) reintroduced by the feature meant to fix it.</p>
 *
 * <p>Three separate bounds are needed and none is redundant.
 * {@link Chunker#MAX_REASSEMBLY_BUFFER} caps the segment bytes held at once
 * across every message, so one large message cannot exhaust memory.
 * {@link Chunker#MAX_CONCURRENT_REASSEMBLIES} caps how many messages may be in
 * flight, because a flood of distinct message ids each carrying an
 * <em>empty</em> segment costs nothing against a byte budget and still costs
 * memory. {@link #TIMEOUT_MILLIS} caps how long a partial may sit, so a message
 * abandoned in flight cannot pin memory for the life of the session.</p>
 *
 * <p>Thread-safe: offer is synchronized, since a node reassembles across
 * multiple neighbor links on separate threads.</p>
 *
 * @author Caleb L. Power
 */
public final class Reassembler {

  /** Milliseconds a partially-filled message may sit before being discarded (&sect;0). */
  public static final long TIMEOUT_MILLIS = 30000L;

  /** Insertion-ordered so the timeout sweep walks oldest-first and can stop early. */
  private final Map<String, Partial> partials = new LinkedHashMap<>();
  private long bufferedBytes;

  /**
   * Offers a data message for reassembly.
   *
   * @param dataMessage an inbound data message
   * @return the reassembled application payload when complete, else empty
   */
  public Optional<JSONObject> offer(JSONObject dataMessage) {
    return offer(dataMessage, System.currentTimeMillis());
  }

  /**
   * Offers a data message for reassembly against an explicit clock reading, so
   * the timeout is testable without sleeping. Package-private: the wire-facing
   * entry point is {@link #offer(JSONObject)}.
   *
   * @param dataMessage an inbound data message
   * @param nowMillis the current time in milliseconds
   * @return the reassembled application payload when complete, else empty
   */
  synchronized Optional<JSONObject> offer(JSONObject dataMessage, long nowMillis) {
    sweep(nowMillis);

    // optJSONObject cannot tell an absent chunk from one that is not an object, and
    // conflating them delivered a message with a garbage chunk as though it were
    // whole -- a divergence from Go, Rust and JS, and from the corpus case
    // data-chunk-not-an-object. has() separates the two.
    if(dataMessage.has("chunk") && dataMessage.optJSONObject("chunk") == null)
      return Optional.empty();
    JSONObject chunk = dataMessage.optJSONObject("chunk");
    int n = chunk == null ? 1 : chunk.optInt("n", -1);
    if(chunk == null || n == 1) {
      // A whole message carries payload and no seg. One claiming n == 1 while
      // carrying seg instead is malformed, not a one-segment split -- and so is
      // one carrying both, which is why the seg check is here and not only in the
      // schema. Found by mutation: without it a message with payload AND seg was
      // delivered, since the payload lookup alone cannot see the contradiction.
      if(dataMessage.has("seg")) return Optional.empty();
      JSONObject payload = dataMessage.optJSONObject("payload");
      return payload == null ? Optional.empty() : Optional.of(payload);
    }

    // Bounds first, allocation second. optInt yields the default for a missing
    // or non-integer field, so a chunk that is not an object, a string index, a
    // fractional count and an out-of-range count all fail together here --
    // before anything is sized on n.
    int i = chunk.optInt("i", -1);
    if(n < 1 || n > Chunker.MAX_CHUNKS || i < 0 || i >= n) return Optional.empty();

    String seg = dataMessage.optString("seg", null);
    if(seg == null) return Optional.empty(); // a segment without its slice

    String mid = dataMessage.getString("mid");
    Partial partial = partials.get(mid);
    if(partial == null) {
      if(partials.size() >= Chunker.MAX_CONCURRENT_REASSEMBLIES) return Optional.empty();
      partial = new Partial(n, nowMillis);
      partials.put(mid, partial);
    } else if(partial.segments.length != n) {
      discard(mid, partial); // the peer changed n mid-message
      return Optional.empty();
    }

    if(partial.segments[i] == null) {
      long size = seg.getBytes(StandardCharsets.UTF_8).length;
      if(bufferedBytes + size > Chunker.MAX_REASSEMBLY_BUFFER) {
        discard(mid, partial);
        return Optional.empty();
      }
      partial.segments[i] = seg;
      partial.bytes += size;
      partial.received++;
      bufferedBytes += size;
    }
    if(partial.received != n) return Optional.empty();

    discard(mid, partial);
    return Optional.of(new JSONObject(String.join("", partial.segments)));
  }

  /**
   * Number of messages currently mid-reassembly. Package-private, for the tests
   * that assert the bounds actually release memory rather than merely refusing
   * to add to it -- a reassembler that rejects a segment but keeps its partial
   * forever is still a leak, and the refusal alone cannot show that.
   *
   * @return the in-flight message count
   */
  synchronized int inFlight() {
    return partials.size();
  }

  /**
   * Segment bytes currently buffered across every in-flight message.
   *
   * @return the buffered byte count
   */
  synchronized long bufferedBytes() {
    return bufferedBytes;
  }

  /**
   * Drops a partial and returns its bytes to the shared budget.
   *
   * @param mid the message id
   * @param partial the partial being dropped
   */
  private void discard(String mid, Partial partial) {
    partials.remove(mid);
    bufferedBytes -= partial.bytes;
  }

  /**
   * Discards every partial that has outlived the reassembly timeout.
   *
   * @param nowMillis the current time in milliseconds
   */
  private void sweep(long nowMillis) {
    Iterator<Map.Entry<String, Partial>> it = partials.entrySet().iterator();
    while(it.hasNext()) {
      Partial partial = it.next().getValue();
      if(nowMillis - partial.startedMillis < TIMEOUT_MILLIS) break; // insertion-ordered: the rest are younger
      it.remove();
      bufferedBytes -= partial.bytes;
    }
  }

  private static final class Partial {
    private final String[] segments;
    private final long startedMillis;
    private int received;
    private long bytes;

    Partial(int n, long startedMillis) {
      this.segments = new String[n];
      this.startedMillis = startedMillis;
    }
  }
}
