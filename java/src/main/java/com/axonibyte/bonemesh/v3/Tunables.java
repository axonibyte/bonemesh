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

package com.axonibyte.bonemesh.v3;

/**
 * A node's operational knobs (protocol.md &sect;0): local behavior, never part
 * of the wire contract, read once from the environment at node start. Two nodes
 * configured with different values still interoperate.
 *
 * @author Caleb L. Power
 */
final class Tunables {

  final long probeTimeoutMillis;
  final long idleMillis;
  final long retryBaseMillis;
  final long retryCapMillis;
  final long retryMaxMillis;
  final long rekeyMillis;
  final long rekeyFrames;
  final long rekeyTimeoutMillis;
  final String keylogPath;

  private Tunables() {
    this.probeTimeoutMillis = envLong("BONEMESH_PROBE_TIMEOUT_MS", 15000L);
    this.idleMillis = envLong("BONEMESH_IDLE_MS", 0L);
    this.retryBaseMillis = envLong("BONEMESH_RETRY_BASE_MS", 500L);
    this.retryCapMillis = envLong("BONEMESH_RETRY_CAP_MS", 30000L);
    this.retryMaxMillis = envLong("BONEMESH_RETRY_MAX_MS", 60000L);
    this.rekeyMillis = envLong("BONEMESH_REKEY_MS", 3600000L);
    this.rekeyFrames = envLong("BONEMESH_REKEY_FRAMES", 65536L);
    this.rekeyTimeoutMillis = envLong("BONEMESH_REKEY_TIMEOUT_MS", 10000L);
    String kl = System.getenv("BONEMESH_KEYLOG");
    this.keylogPath = kl == null ? "" : kl;
  }

  /** @return the tunables resolved from the current environment */
  static Tunables load() {
    return new Tunables();
  }

  private static long envLong(String name, long fallback) {
    String v = System.getenv(name);
    if(v == null || v.isEmpty()) return fallback;
    try {
      return Long.parseLong(v.trim());
    } catch(NumberFormatException e) {
      return fallback;
    }
  }
}
