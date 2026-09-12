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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;

/**
 * Splitting and reassembly tests (protocol.md &sect;6.1).
 *
 * <p>Two groups. The first pins the <em>format</em>: a small payload passes
 * through whole, a large one splits and rebuilds byte-identically, every segment
 * satisfies the data schema, a segment carries no payload, segments are text
 * rather than Base64, and cuts land on character boundaries even when the
 * payload is multi-byte throughout.</p>
 *
 * <p>The second pins the <em>bounds</em>, which is the half that had no coverage
 * at all and where the defect was. Each asserts that a hostile or malformed
 * message is refused <em>and</em> that refusing it released whatever it had
 * claimed -- a reassembler that rejects a segment but keeps its partial forever
 * is still a leak, and one oracle cannot see that.</p>
 */
public class ChunkerTest {

  private static final String MID = "0".repeat(32);

  private static String big(int chars) {
    StringBuilder sb = new StringBuilder(chars);
    for(int i = 0; i < chars; i++) sb.append((char) ('a' + (i % 26)));
    return sb.toString();
  }

  private static JSONObject segment(String mid, int i, int n, String seg) {
    return Messages.dataSegment(mid, "a", "b", 16, i, n, seg);
  }

  // ---- format ----

  @Test void smallPayloadIsWhole() {
    JSONObject payload = new JSONObject().put("line", "hello");
    List<JSONObject> msgs = Chunker.split(MID, "a", "b", 16, payload);
    assertEquals(1, msgs.size());
    assertFalse(msgs.get(0).has("chunk"));
    assertFalse(msgs.get(0).has("seg"), "a whole message must not carry seg");
    assertEquals(payload.toString(), msgs.get(0).getJSONObject("payload").toString());
  }

  @Test void largePayloadSplitsAndReassembles() {
    JSONObject payload = new JSONObject().put("blob", big(120_000));
    List<JSONObject> msgs = Chunker.split(MID, "a", "b", 16, payload);
    assertTrue(msgs.size() > 1, "large payload was not split");

    int n = msgs.size();
    for(int i = 0; i < n; i++) {
      JSONObject m = msgs.get(i);
      assertNull(MessageSchema.validate("data", m), "segment failed schema: " + i);
      assertEquals(n, m.getJSONObject("chunk").getInt("n"));
      assertEquals(i, m.getJSONObject("chunk").getInt("i"));
      assertFalse(m.has("payload"), "segment " + i + " carries a payload");
      assertTrue(m.get("seg") instanceof String, "segment " + i + " is not a string");
      assertTrue(m.getString("seg").getBytes(StandardCharsets.UTF_8).length <= Chunker.MAX_SEGMENT_BYTES,
          "segment " + i + " is over the pinned maximum");
    }

    Reassembler r = new Reassembler();
    for(int i = 0; i < n - 1; i++) assertTrue(r.offer(msgs.get(i)).isEmpty());
    Optional<JSONObject> done = r.offer(msgs.get(n - 1));
    assertTrue(done.isPresent());
    assertEquals(payload.toString(), done.get().toString());
    assertEquals(0, r.inFlight(), "a completed message stayed in the buffer");
    assertEquals(0L, r.bufferedBytes(), "a completed message stayed counted");
  }

  @Test void segmentsAreTextNotBase64() {
    // decision #25: a segment is a slice of the payload's JSON text, so it stays
    // readable through the key-log inspector. Concatenating the segments must
    // reproduce the serialized payload directly, with no decode step.
    JSONObject payload = new JSONObject().put("blob", big(60_000));
    List<JSONObject> msgs = Chunker.split(MID, "a", "b", 16, payload);
    StringBuilder joined = new StringBuilder();
    for(JSONObject m : msgs) joined.append(m.getString("seg"));
    assertEquals(payload.toString(), joined.toString());
    assertTrue(msgs.get(0).getString("seg").startsWith("{"),
        "the first segment should open the payload's JSON, not a Base64 blob");
  }

  @Test void cutsLandOnCharacterBoundaries() {
    // Every character is 3 UTF-8 bytes, so 24000 divides unevenly and a naive
    // byte cut would split one. Each segment must still decode on its own, and
    // the whole must rebuild exactly.
    JSONObject payload = new JSONObject().put("cjk", "日".repeat(40_000));
    List<JSONObject> msgs = Chunker.split(MID, "a", "b", 16, payload);
    assertTrue(msgs.size() > 1);
    for(JSONObject m : msgs) {
      String seg = m.getString("seg");
      byte[] bytes = seg.getBytes(StandardCharsets.UTF_8);
      assertEquals(seg, new String(bytes, StandardCharsets.UTF_8),
          "segment does not round-trip through UTF-8, so a cut split a character");
      assertTrue(bytes.length <= Chunker.MAX_SEGMENT_BYTES);
    }
    Reassembler r = new Reassembler();
    Optional<JSONObject> done = Optional.empty();
    for(JSONObject m : msgs) done = r.offer(m);
    assertTrue(done.isPresent());
    assertEquals(payload.toString(), done.get().toString());
  }

  @Test void outOfOrderSegmentsStillReassemble() {
    JSONObject payload = new JSONObject().put("blob", big(120_000));
    List<JSONObject> msgs = Chunker.split(MID, "a", "b", 16, payload);
    Reassembler r = new Reassembler();
    Optional<JSONObject> done = Optional.empty();
    for(int i = msgs.size() - 1; i >= 0; i--) done = r.offer(msgs.get(i));
    assertTrue(done.isPresent());
    assertEquals(payload.toString(), done.get().toString());
  }

  // ---- bounds ----

  @Test void absurdChunkCountIsRefusedBeforeAllocating() {
    // The defect: the old reassembler sized an array on the peer's n before
    // validating it, so one frame claiming two billion segments raised
    // OutOfMemoryError at -Xmx64m. Both oracles matter -- the offer is refused,
    // AND nothing was retained, which is what proves no allocation happened.
    Reassembler r = new Reassembler();
    for(int n : new int[] { Integer.MAX_VALUE, 2_000_000_000, 1_000_000, Chunker.MAX_CHUNKS + 1 }) {
      assertTrue(r.offer(segment(MID, 0, n, "x")).isEmpty(), "accepted n=" + n);
      assertEquals(0, r.inFlight(), "n=" + n + " was buffered anyway");
      assertEquals(0L, r.bufferedBytes(), "n=" + n + " was counted anyway");
    }
    // The boundary itself is legal, so the check is a bound and not a blanket ban.
    assertTrue(r.offer(segment(MID, 0, Chunker.MAX_CHUNKS, "x")).isEmpty());
    assertEquals(1, r.inFlight(), "the maximum legal chunk count was refused");
  }

  @Test void malformedChunkMetadataIsRefused() {
    Reassembler r = new Reassembler();
    List<JSONObject> bad = new ArrayList<>();
    bad.add(segment(MID, 0, 3, "x").put("chunk", "not-an-object"));
    bad.add(segment(MID, 0, 3, "x").put("chunk", new JSONObject().put("i", "zero").put("n", 3)));
    bad.add(segment(MID, 0, 3, "x").put("chunk", new JSONObject().put("i", 0)));        // no n
    bad.add(segment(MID, 0, 3, "x").put("chunk", new JSONObject().put("n", 3)));        // no i
    bad.add(segment(MID, 3, 3, "x"));                                                  // i == n
    bad.add(segment(MID, -1, 3, "x"));                                                 // i < 0
    bad.add(segment(MID, 0, 0, "x"));                                                  // n == 0
    for(JSONObject m : bad) {
      assertTrue(r.offer(m).isEmpty(), "accepted malformed chunk: " + m.opt("chunk"));
      assertEquals(0, r.inFlight(), "malformed chunk was buffered: " + m.opt("chunk"));
    }
  }

  @Test void segmentWithoutItsSliceIsRefused() {
    Reassembler r = new Reassembler();
    JSONObject m = segment(MID, 0, 3, "x");
    m.remove("seg");
    assertTrue(r.offer(m).isEmpty());
    assertEquals(0, r.inFlight());
  }

  @Test void aWholeMessageClaimingToBeASegmentIsNotDelivered() {
    // n == 1 with seg instead of payload is malformed, not a one-segment split.
    // If this were delivered the exclusion rule would be decorative.
    Reassembler r = new Reassembler();
    assertTrue(r.offer(segment(MID, 0, 1, "{\"a\":1}")).isEmpty());
    assertNotNull(MessageSchema.validate("data", segment(MID, 0, 1, "{\"a\":1}")));
  }

  @Test void aMessageCarryingBothPayloadAndSegmentIsNotDelivered() {
    // Found by mutation. The reassembler's whole-message path looked up payload
    // and returned it, so a message contradicting itself -- payload AND seg --
    // was delivered. The schema rejected it, but the schema is not on the wire
    // path (decision #27), so the reassembler has to refuse it too.
    Reassembler r = new Reassembler();
    JSONObject both = Messages.data(MID, "a", "b", 16, new JSONObject().put("x", 1)).put("seg", "{");
    assertTrue(r.offer(both).isEmpty(), "a self-contradicting message was delivered");
    JSONObject bothWithChunk = segment(MID, 0, 1, "{").put("payload", new JSONObject().put("x", 1));
    assertTrue(r.offer(bothWithChunk).isEmpty(), "a self-contradicting n==1 message was delivered");
  }

  @Test void aNonObjectChunkIsRefusedEvenWithAPayload() {
    // The distinguishing input, and the one nothing tested: a garbage chunk on a
    // message that DOES carry a payload. Java conflated "chunk absent" with
    // "chunk unparseable" and delivered it, where Go, Rust and JS refused -- and
    // where corpus case data-chunk-not-an-object says invalid. chunk is a
    // specified field with a specified type, so a wrong type is malformed; §8's
    // tolerance covers unknown fields and unrecognised inner types, not this.
    Reassembler r = new Reassembler();
    for(Object garbage : new Object[] { "1/3", 7, new org.json.JSONArray() }) {
      JSONObject m = Messages.data(MID, "a", "b", 16, new JSONObject().put("x", 1)).put("chunk", garbage);
      assertTrue(r.offer(m).isEmpty(), "delivered a message whose chunk was " + garbage.getClass().getSimpleName());
      assertNotNull(MessageSchema.validate("data", m), "the schema should reject it too");
    }
  }

  @Test void concurrentReassembliesAreBounded() {
    Reassembler r = new Reassembler();
    for(int k = 0; k < Chunker.MAX_CONCURRENT_REASSEMBLIES; k++)
      assertTrue(r.offer(segment(String.format("%032x", k), 0, 4, "x")).isEmpty());
    assertEquals(Chunker.MAX_CONCURRENT_REASSEMBLIES, r.inFlight());
    // One past the bound is refused, and refusing it does not disturb the rest.
    assertTrue(r.offer(segment(String.format("%032x", 9999), 0, 4, "x")).isEmpty());
    assertEquals(Chunker.MAX_CONCURRENT_REASSEMBLIES, r.inFlight());
  }

  @Test void bufferedBytesAreBounded() {
    // The concurrent-message bound (256) is reached long before 16 MiB of
    // segments can be spread across separate message ids, so the byte budget is
    // only reachable inside one message -- 1024 segments of 24000 bytes is
    // 24.5 MB, over the 16 MiB ceiling. That is the case to drive, and getting
    // it wrong the first time is why the assertion names which bound binds.
    Reassembler r = new Reassembler();
    String full = "y".repeat(Chunker.MAX_SEGMENT_BYTES);
    int accepted = 0;
    for(int i = 0; i < Chunker.MAX_CHUNKS; i++) {
      r.offer(segment(MID, i, Chunker.MAX_CHUNKS, full));
      if(r.inFlight() == 0) break; // the message was abandoned: the budget refused it
      accepted++;
      assertTrue(r.bufferedBytes() <= Chunker.MAX_REASSEMBLY_BUFFER,
          "the buffer maximum was exceeded at segment " + i);
    }
    assertTrue(accepted > 0 && accepted < Chunker.MAX_CHUNKS,
        "expected the byte budget to stop an over-large message partway, stopped at " + accepted);
    assertEquals(Chunker.MAX_REASSEMBLY_BUFFER / Chunker.MAX_SEGMENT_BYTES, accepted,
        "the message should be abandoned on the first segment that would not fit");
    assertEquals(0, r.inFlight(), "the abandoned message was retained");
    assertEquals(0L, r.bufferedBytes(), "abandoning the message did not return its bytes");
  }

  @Test void stalePartialsAreSwept() {
    Reassembler r = new Reassembler();
    assertTrue(r.offer(segment(MID, 0, 3, "x"), 1_000L).isEmpty());
    assertEquals(1, r.inFlight());
    // Just inside the timeout: still held.
    assertTrue(r.offer(segment(MID, 1, 3, "y"), 1_000L + Reassembler.TIMEOUT_MILLIS - 1).isEmpty());
    assertEquals(1, r.inFlight());
    // At the timeout, the partial is gone and its bytes are back.
    assertTrue(r.offer(segment("1".repeat(32), 0, 3, "z"), 1_000L + Reassembler.TIMEOUT_MILLIS).isEmpty());
    assertEquals(1, r.inFlight(), "the stale partial was not swept");
    assertEquals(1L, r.bufferedBytes(), "swept bytes were not returned to the budget");
  }

  @Test void theSchemaEnforcesTheWholeExclusionRule() {
    // Found by mutation: deleting the "both or neither" line left every test
    // green, because the n == 1 and n > 1 clauses below it covered the only
    // cases the suite exercised. The uncovered half was a data message carrying
    // NEITHER payload nor seg, and a data message carrying BOTH.
    JSONObject neither = Messages.data(MID, "a", "b", 16, new JSONObject().put("x", 1));
    neither.remove("payload");
    assertEquals("missing-field", MessageSchema.validate("data", neither),
        "an absent field should keep the reason the corpus has pinned since 3.0.0");

    JSONObject both = segment(MID, 0, 3, "{\"x\":1}").put("payload", new JSONObject().put("x", 1));
    assertEquals("payload-or-seg", MessageSchema.validate("data", both));

    JSONObject bothWhole = Messages.data(MID, "a", "b", 16, new JSONObject().put("x", 1)).put("seg", "{");
    assertEquals("payload-or-seg", MessageSchema.validate("data", bothWhole));

    // And the legal forms still pass, so this is a rule and not a blanket ban.
    assertNull(MessageSchema.validate("data", Messages.data(MID, "a", "b", 16, new JSONObject().put("x", 1))));
    assertNull(MessageSchema.validate("data", segment(MID, 0, 3, "{\"x\":1}")));
  }

  @Test void theSchemaBoundsChunkMetadata() {
    assertEquals("chunk-format", MessageSchema.validate("data",
        segment(MID, 0, 3, "x").put("chunk", "not-an-object")));
    assertEquals("chunk-format", MessageSchema.validate("data",
        segment(MID, 0, 3, "x").put("chunk", new JSONObject().put("i", "zero").put("n", 3))));
    assertEquals("chunk-range", MessageSchema.validate("data", segment(MID, 0, 0, "x")));
    assertEquals("chunk-range", MessageSchema.validate("data",
        segment(MID, 0, Chunker.MAX_CHUNKS + 1, "x")));
    assertEquals("chunk-range", MessageSchema.validate("data", segment(MID, 3, 3, "x")));
    assertNull(MessageSchema.validate("data", segment(MID, 1023, Chunker.MAX_CHUNKS, "x")),
        "the boundary itself must be legal");
  }

  @Test void anOversizedPayloadFailsAtTheOrigin() {
    // §6.1: an origin whose payload no conforming destination would reassemble
    // must be told locally rather than emitting it.
    JSONObject payload = new JSONObject().put("blob", big(Chunker.MAX_REASSEMBLY_BUFFER + 1));
    assertThrows(IllegalArgumentException.class, () -> Chunker.split(MID, "a", "b", 16, payload));
  }
}
