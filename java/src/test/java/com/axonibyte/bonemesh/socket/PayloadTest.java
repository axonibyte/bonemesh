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

package com.axonibyte.bonemesh.socket;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.TimeUnit;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the retry schedule carried by {@link Payload} (defect D6).
 * Delay assertions allow a little wall-clock slack; the schedule is computed
 * from System.currentTimeMillis().
 */
public class PayloadTest {

  @Test void freshPayloadIsImmediatelyEligible() {
    Payload payload = new Payload(new JSONObject(), "target", true);
    assertTrue(payload.getDelay(TimeUnit.MILLISECONDS) <= 0L);
  }

  @Test void firstFailureBacksOff() {
    Payload payload = new Payload(new JSONObject(), "target", true);
    payload.recordFailure();
    long delay = payload.getDelay(TimeUnit.MILLISECONDS);
    assertTrue(delay > 0L, "no backoff after a failure: " + delay);
    assertTrue(delay <= 500L, "initial backoff too large: " + delay);
  }

  @Test void backoffGrowsWithConsecutiveFailures() {
    Payload payload = new Payload(new JSONObject(), "target", true);
    payload.recordFailure();
    long first = payload.getDelay(TimeUnit.MILLISECONDS);
    payload.recordFailure();
    long second = payload.getDelay(TimeUnit.MILLISECONDS);
    assertTrue(second > first, "backoff did not grow: " + first + " -> " + second);
  }

  @Test void backoffIsBounded() {
    Payload payload = new Payload(new JSONObject(), "target", true);
    for(int i = 0; i < 64; i++) payload.recordFailure();
    long delay = payload.getDelay(TimeUnit.MILLISECONDS);
    assertTrue(delay <= 30_000L, "backoff exceeded its bound: " + delay);
    assertTrue(delay > 25_000L, "backoff collapsed instead of capping: " + delay);
  }
}
