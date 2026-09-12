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
import java.util.Arrays;
import java.util.List;

import org.json.JSONObject;

/**
 * Splits an oversized application payload across several data messages
 * (protocol.md &sect;6.1), all sharing one message id, so the frame size cap
 * never limits application data.
 *
 * <p>The payload is serialized to JSON and its UTF-8 bytes are cut into segments
 * of at most {@link #MAX_SEGMENT_BYTES}, every cut landing on a character
 * boundary. Segment {@code i} of {@code n} travels as a data message carrying
 * {@code chunk = {i, n}} and a top-level {@code seg} string, and carrying
 * <em>no</em> {@code payload}. A payload that fits in one segment is sent whole,
 * with {@code payload} and no {@code seg}.</p>
 *
 * <p>Segments are text, not Base64. &sect;0's Base64 rule covers binary fields;
 * a slice of JSON text is already UTF-8 and a JSON string carries it directly,
 * which keeps a split message readable through the key-log inspector
 * (decisions #3, #5, #25). Cutting on a byte budget rather than a character
 * count is what makes the split identical in every language: UTF-8 has no
 * surrogates, so the UTF-16-versus-code-point divergence that
 * {@code security.md} &sect;11.1 has to legislate for canonicalization cannot
 * arise here.</p>
 *
 * <p>Reassembly is {@link Reassembler}.</p>
 *
 * @author Caleb L. Power
 */
public final class Chunker {

  /** Maximum payload bytes carried by one segment (protocol.md &sect;0). */
  public static final int MAX_SEGMENT_BYTES = 24000;

  /** Maximum segments one application message may be split into (&sect;0). */
  public static final int MAX_CHUNKS = 1024;

  /** Maximum segment bytes buffered at once, across every in-flight message (&sect;0). */
  public static final int MAX_REASSEMBLY_BUFFER = 16777216;

  /** Maximum messages that may be mid-reassembly at once (&sect;0). */
  public static final int MAX_CONCURRENT_REASSEMBLIES = 256;

  private Chunker() { }

  /**
   * Splits a payload into one whole data message or a series of segments.
   *
   * @param mid the shared message id
   * @param from the origin label
   * @param to the destination label
   * @param ttl the hop limit
   * @param payload the application payload
   * @return the data messages to send, in ascending segment order
   * @throws IllegalArgumentException if the payload exceeds what any conforming
   *         destination will reassemble, so the caller is told locally rather
   *         than the message being emitted and silently dropped downstream
   */
  public static List<JSONObject> split(String mid, String from, String to, int ttl, JSONObject payload) {
    byte[] src = payload.toString().getBytes(StandardCharsets.UTF_8);
    List<JSONObject> out = new ArrayList<>();
    if(src.length <= MAX_SEGMENT_BYTES) {
      out.add(Messages.data(mid, from, to, ttl, payload)); // whole
      return out;
    }
    if(src.length > MAX_REASSEMBLY_BUFFER)
      throw new IllegalArgumentException(
          "payload of " + src.length + " bytes exceeds the reassembly buffer maximum of " + MAX_REASSEMBLY_BUFFER);

    List<byte[]> segments = new ArrayList<>();
    int pos = 0;
    while(pos < src.length) {
      int end = charBoundary(src, pos, Math.min(pos + MAX_SEGMENT_BYTES, src.length));
      segments.add(Arrays.copyOfRange(src, pos, end));
      pos = end;
    }
    if(segments.size() > MAX_CHUNKS)
      throw new IllegalArgumentException(
          "payload needs " + segments.size() + " segments, over the maximum of " + MAX_CHUNKS);

    int n = segments.size();
    for(int i = 0; i < n; i++)
      out.add(Messages.dataSegment(mid, from, to, ttl, i, n,
          new String(segments.get(i), StandardCharsets.UTF_8)));
    return out;
  }

  /**
   * Walks a proposed cut back to the nearest character boundary at or before it,
   * so a segment never ends mid-character and is always itself valid UTF-8.
   *
   * @param src the payload's UTF-8 bytes
   * @param start where this segment begins
   * @param end the proposed cut
   * @return the cut, moved back off any continuation byte
   */
  private static int charBoundary(byte[] src, int start, int end) {
    if(end >= src.length) return end; // the tail is always a boundary
    int e = end;
    while(e > start && (src[e] & 0xC0) == 0x80) e--; // 10xxxxxx is a continuation byte
    // A UTF-8 character is at most 4 bytes and a segment is 24000, so e can never
    // reach start from well-formed input; falling back to the unmoved cut keeps a
    // malformed serializer from producing a zero-length segment and looping forever.
    return e > start ? e : end;
  }
}
