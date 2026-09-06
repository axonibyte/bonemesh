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

import java.security.SecureRandom;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;

/**
 * Message construction, validation, id, and dedup tests. Cross-language
 * agreement with the Go validator over spec/corpus/messages.json is checked
 * separately by interop/check-messages.sh (see MessageCheck).
 */
public class MessageTest {

  private static final SecureRandom RNG = new SecureRandom();

  @Test void newMidIs32LowercaseHex() {
    String mid = Messages.newMid(RNG);
    assertEquals(32, mid.length());
    assertTrue(mid.matches("[0-9a-f]{32}"), "mid was not 32 lowercase hex: " + mid);
  }

  @Test void midsAreDistinct() {
    assertFalse(Messages.newMid(RNG).equals(Messages.newMid(RNG)));
  }

  // Every builder must produce a message its schema accepts.
  @Test void builtMessagesPassTheirSchema() {
    String mid = Messages.newMid(RNG);
    assertNull(MessageSchema.validate("data",
        Messages.data(mid, "alpha", "gamma", Messages.DEFAULT_TTL, new JSONObject().put("line", "hi"))));
    assertNull(MessageSchema.validate("ack", Messages.ack(mid)));
    assertNull(MessageSchema.validate("nak",
        Messages.nak(mid, "beta", "alpha", "charlie", "ttl", Messages.DEFAULT_TTL)));
    assertNull(MessageSchema.validate("bye", Messages.bye()));
    assertNull(MessageSchema.validate("bye", Messages.bye("idle")));
  }

  // nak is routed like data (to/from/ttl) plus hop/reason; the reason value is
  // not enum-checked, so an unrecognized reason string is still valid.
  @Test void nakSchemaVerdicts() {
    String mid = Messages.newMid(RNG);
    assertNull(MessageSchema.validate("nak", Messages.nak(mid, "b", "a", "c", "future-reason", 16)));
    assertEquals("type", MessageSchema.validate("nak",
        new JSONObject().put("type", "data").put("mid", mid).put("hop", "c")
            .put("reason", "ttl").put("to", "a").put("from", "b").put("ttl", 16)));
    assertEquals("mid-format", MessageSchema.validate("nak",
        Messages.nak("0123", "b", "a", "c", "ttl", 16)));
    assertEquals("missing-field", MessageSchema.validate("nak",
        new JSONObject().put("type", "nak").put("mid", mid)
            .put("reason", "ttl").put("to", "a").put("from", "b").put("ttl", 16)));
    assertEquals("missing-field", MessageSchema.validate("nak",
        new JSONObject().put("type", "nak").put("mid", mid).put("hop", "c")
            .put("to", "a").put("from", "b").put("ttl", 16)));
    assertEquals("ttl-range", MessageSchema.validate("nak",
        Messages.nak(mid, "b", "a", "c", "ttl", 0)));
  }

  // bye is link-local: only its type is required; reason is optional and free.
  @Test void byeSchemaVerdicts() {
    assertNull(MessageSchema.validate("bye", Messages.bye("idle")));
    assertNull(MessageSchema.validate("bye", Messages.bye()));
    assertNull(MessageSchema.validate("bye", Messages.bye("some-future-reason")));
    assertEquals("type", MessageSchema.validate("bye", new JSONObject().put("type", "data")));
  }

  @Test void dataWithBadTtlFailsSchema() {
    String mid = Messages.newMid(RNG);
    JSONObject bad = Messages.data(mid, "a", "b", 300, new JSONObject());
    assertEquals("ttl-range", MessageSchema.validate("data", bad));
  }

  @Test void dataWithMalformedMidFailsSchema() {
    JSONObject shortMid = Messages.data("0123", "a", "b", 16, new JSONObject());
    assertEquals("mid-format", MessageSchema.validate("data", shortMid));
    JSONObject upperMid = Messages.data("0123456789ABCDEF0123456789ABCDEF", "a", "b", 16, new JSONObject());
    assertEquals("mid-format", MessageSchema.validate("data", upperMid));
  }

  @Test void wrongTypeFailsSchema() {
    assertEquals("type", MessageSchema.validate("data", Messages.ack(Messages.newMid(RNG))));
  }

  @Test void dedupReportsRepeatsAndForgetsEldest() {
    Dedup dedup = new Dedup(3);
    assertFalse(dedup.seenBefore("a"));
    assertTrue(dedup.seenBefore("a"));      // immediate repeat
    assertFalse(dedup.seenBefore("b"));
    assertFalse(dedup.seenBefore("c"));
    assertFalse(dedup.seenBefore("d"));     // evicts "a" (capacity 3)
    assertEquals(3, dedup.size());
    assertFalse(dedup.seenBefore("a"));     // "a" was forgotten, so it is new again
  }
}
