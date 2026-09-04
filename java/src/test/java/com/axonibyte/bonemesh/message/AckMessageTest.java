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

package com.axonibyte.bonemesh.message;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for ack serialization (defect D9: the pubkey a responder
 * attaches to its ack must survive every re-parse of that ack).
 */
public class AckMessageTest {

  @Test void ackBuiltFromARequestFlipsAddressing() {
    JSONObject request = new JSONObject()
        .put("from", "alpha")
        .put("to", "beta")
        .put("action", "generic")
        .put("payload", new JSONObject());
    AckMessage ack = new AckMessage(request, true);
    assertEquals("beta", ack.getFrom());
    assertEquals("alpha", ack.getTo());
    assertFalse(ack.hasPubkey());
  }

  @Test void reParsedAckKeepsItsPubkey() {
    AckMessage original = new AckMessage("beta", "alpha");
    original.setPubkey("PK");
    AckMessage reParsed = new AckMessage(new JSONObject(original.toString()), false);
    assertTrue(reParsed.hasPubkey());
    assertEquals("PK", reParsed.getPubkey());
  }

  @Test void pubkeyConstructorCarriesTheKey() {
    AckMessage ack = new AckMessage("beta", "alpha", "PK");
    assertTrue(ack.hasPubkey());
    assertEquals("PK", ack.getPubkey());
  }
}
