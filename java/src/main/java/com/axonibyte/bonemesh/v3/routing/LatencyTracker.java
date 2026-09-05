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

package com.axonibyte.bonemesh.v3.routing;

/**
 * An exponentially-weighted moving average of round-trip-time samples for one
 * neighbor (protocol.md &sect;5). This is the real fix for defect D3: v2's
 * "latency" was time since the last heartbeat tick, meaningless as a routing
 * metric; v3 measures actual RTT via probe/echo and smooths it here, so a
 * transient spike does not dominate route selection.
 *
 * @author Caleb L. Power
 */
public final class LatencyTracker {

  /** Default smoothing factor (protocol.md §0 tunable). */
  public static final double DEFAULT_ALPHA = 0.2;

  private final double alpha;
  private double ewma = -1.0; // -1 until the first sample

  /**
   * Creates a tracker with the default smoothing factor.
   */
  public LatencyTracker() {
    this(DEFAULT_ALPHA);
  }

  /**
   * @param alpha the smoothing factor in (0, 1]; higher reacts faster
   */
  public LatencyTracker(double alpha) {
    if(!(alpha > 0.0 && alpha <= 1.0))
      throw new IllegalArgumentException("alpha must be in (0, 1]");
    this.alpha = alpha;
  }

  /**
   * Folds in a new RTT sample.
   *
   * @param sampleMillis the measured round-trip time in milliseconds
   */
  public void update(long sampleMillis) {
    if(sampleMillis < 0) throw new IllegalArgumentException("RTT sample cannot be negative");
    ewma = ewma < 0.0 ? sampleMillis : alpha * sampleMillis + (1.0 - alpha) * ewma;
  }

  /**
   * @return the current EWMA latency in milliseconds, rounded; or
   *         {@link Long#MAX_VALUE} if no sample has been recorded (unknown)
   */
  public long latencyMillis() {
    return ewma < 0.0 ? Long.MAX_VALUE : Math.round(ewma);
  }

  /**
   * @return <code>true</code> once at least one sample has been recorded
   */
  public boolean hasSample() {
    return ewma >= 0.0;
  }
}
