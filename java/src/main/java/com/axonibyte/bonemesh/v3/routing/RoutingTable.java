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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * The BoneMesh v3 routing table (protocol.md &sect;6): direct neighbors with
 * measured link latencies, and a distance-vector routing table of
 * indirectly-reachable destinations. Improvements over v2: costs are real
 * latencies (defect D3), sums saturate rather than overflowing a dead-node
 * sentinel, the node's own label is never a route, and advertisements apply
 * split-horizon with poisoned reverse to bound count-to-infinity.
 *
 * <p>Thread-safe: every public method is synchronized, because the node drives
 * one table concurrently from a heartbeat thread and one reader thread per
 * neighbor.</p>
 *
 * @author Caleb L. Power
 */
public final class RoutingTable {

  /** Sentinel path cost meaning "unreachable" (used in poisoned advertisements). */
  public static final long UNREACHABLE = Long.MAX_VALUE;

  private final String selfLabel;
  private final Map<String, LatencyTracker> neighbors = new HashMap<>();
  private final Map<String, Route> routes = new HashMap<>();

  /**
   * @param selfLabel this node's label (never installed as a route)
   */
  public RoutingTable(String selfLabel) {
    this.selfLabel = selfLabel;
  }

  /**
   * Records or updates a neighbor and folds in an RTT sample.
   *
   * @param label the neighbor's label
   * @param rttSampleMillis a measured round-trip-time sample
   */
  public synchronized void observeNeighbor(String label, long rttSampleMillis) {
    neighbors.computeIfAbsent(label, k -> new LatencyTracker()).update(rttSampleMillis);
  }

  /**
   * Removes a neighbor and withdraws every route that went through it (defect
   * D4's converse: a dead neighbor's routes are poisoned, not left stale).
   *
   * @param label the neighbor's label
   */
  public synchronized void removeNeighbor(String label) {
    neighbors.remove(label);
    routes.entrySet().removeIf(e -> e.getValue().via.equalsIgnoreCase(label));
  }

  /** @return the measured latency to a direct neighbor, or MAX_VALUE if unknown */
  public synchronized long neighborLatency(String label) {
    LatencyTracker t = neighbors.get(label);
    return t == null ? UNREACHABLE : t.latencyMillis();
  }

  /** @return whether the label is a direct neighbor */
  public synchronized boolean isNeighbor(String label) {
    return neighbors.containsKey(label);
  }

  /**
   * Learns a route to {@code dest} advertised by {@code viaNeighbor} at the
   * given cost, installing it if new or strictly better. The effective cost is
   * the advertised cost plus the latency to the advertising neighbor, saturated.
   *
   * @param dest the destination label
   * @param viaNeighbor the advertising direct neighbor
   * @param advertisedCost the neighbor's advertised path cost to dest
   */
  public synchronized void learnRoute(String dest, String viaNeighbor, long advertisedCost) {
    if(dest.equalsIgnoreCase(selfLabel)) return;         // never route to ourselves
    if(dest.equalsIgnoreCase(viaNeighbor)) return;       // that is just the neighbor itself
    if(!neighbors.containsKey(viaNeighbor)) return;      // only learn via known neighbors
    if(advertisedCost == UNREACHABLE) {                  // poisoned: withdraw if we used this via
      Route existing = routes.get(key(dest));
      if(existing != null && existing.via.equalsIgnoreCase(viaNeighbor)) routes.remove(key(dest));
      return;
    }
    long cost = saturatingSum(advertisedCost, neighborLatency(viaNeighbor));
    Route existing = routes.get(key(dest));
    if(existing == null || existing.via.equalsIgnoreCase(viaNeighbor) || cost < existing.cost)
      routes.put(key(dest), new Route(viaNeighbor, cost));
  }

  /**
   * Selects the next hop toward a destination: the destination itself if it is
   * a direct neighbor, otherwise the neighbor named by the best route.
   *
   * @param dest the destination label
   * @return the next-hop neighbor label, or {@code null} if unreachable
   */
  public synchronized String nextHop(String dest) {
    if(neighbors.containsKey(dest)) return dest;
    for(var e : neighbors.entrySet())
      if(e.getKey().equalsIgnoreCase(dest)) return e.getKey();
    Route r = routes.get(key(dest));
    return r == null ? null : r.via;
  }

  /**
   * Builds the advertisement to send to {@code toNeighbor}, applying
   * split-horizon with poisoned reverse: a route learned through
   * {@code toNeighbor} is advertised back to it as {@link #UNREACHABLE} rather
   * than at its real cost, which stops a two-node routing loop from counting to
   * infinity. Direct neighbors are advertised at their measured latency; our own
   * label is never advertised.
   *
   * @param toNeighbor the neighbor the advertisement is for
   * @return a map of destination label to advertised cost
   */
  public synchronized Map<String, Long> advertiseTo(String toNeighbor) {
    Map<String, Long> advert = new HashMap<>();
    for(var e : neighbors.entrySet()) {
      if(e.getKey().equalsIgnoreCase(toNeighbor)) continue; // no need to tell them about themselves
      advert.put(e.getKey(), e.getValue().latencyMillis());
    }
    for(var e : routes.entrySet()) {
      Route r = e.getValue();
      long cost = r.via.equalsIgnoreCase(toNeighbor) ? UNREACHABLE : r.cost; // poisoned reverse
      advert.put(e.getKey(), cost);
    }
    advert.remove(key(selfLabel));
    return advert;
  }

  private static long saturatingSum(long a, long b) {
    long sum = a + b;
    return ((a ^ sum) & (b ^ sum)) < 0 ? Long.MAX_VALUE : sum;
  }

  private static String key(String label) {
    return label.toLowerCase(java.util.Locale.ROOT);
  }

  private static final class Route {
    final String via;
    final long cost;

    Route(String via, long cost) {
      this.via = via;
      this.cost = cost;
    }
  }

  /** @return an unmodifiable snapshot of known destination labels (routes only) */
  public synchronized Set<String> knownRouteDestinations() {
    return new HashSet<>(routes.keySet());
  }
}
