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

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A bounded, per-peer dedup window over message ids (protocol.md &sect;4): a
 * message id already seen within the window is a duplicate — the mechanism that
 * lets a retried or re-relayed message be dropped once. Eldest ids fall out
 * when the window is full.
 *
 * <p>Thread-safe: access is synchronized, since a node handles multiple neighbor links on separate threads.</p>
 *
 * @author Caleb L. Power
 */
public final class Dedup {

  private final int capacity;
  private final LinkedHashMap<String, Boolean> seen;

  /**
   * @param capacity the number of recent ids to remember
   */
  public Dedup(int capacity) {
    if(capacity < 1) throw new IllegalArgumentException("capacity must be positive");
    this.capacity = capacity;
    this.seen = new LinkedHashMap<>(16, 0.75f, false) {
      @Override protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest) {
        return size() > Dedup.this.capacity;
      }
    };
  }

  /**
   * Records a message id and reports whether it is a duplicate.
   *
   * @param mid the message id
   * @return <code>true</code> if this id was already in the window (a
   *         duplicate); <code>false</code> if it is new (and now recorded)
   */
  public synchronized boolean seenBefore(String mid) {
    if(seen.containsKey(mid)) return true;
    seen.put(mid, Boolean.TRUE);
    return false;
  }

  /**
   * @return the number of ids currently remembered
   */
  public synchronized int size() {
    return seen.size();
  }
}
