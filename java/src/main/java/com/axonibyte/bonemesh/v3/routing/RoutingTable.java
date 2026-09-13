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

  // Every label in both maps is folded through key() before use, so lookups,
  // advertisements and withdrawals all agree. That was not true before 3.3.0: the
  // neighbors map alone was keyed by the label exactly as given, while routes were
  // folded, which had three consequences and none of them was local.
  //
  //   - advertiseTo emitted neighbor keys in their original case and route keys
  //     folded, so this port's disco.routes differed on the wire from the other six.
  //   - learnRoute's "only learn via known neighbors" guard was case-sensitive, so an
  //     advertisement naming a via in different case was silently dropped -- the other
  //     six folded first and learned it.
  //   - observeNeighbor("Beta", ...) and observeNeighbor("beta", ...) produced two
  //     neighbor entries here and one everywhere else.
  //
  // security.md §2 says labels compare case-insensitively, so folding is what the spec
  // asked for; nextHop's linear equalsIgnoreCase scan was a workaround on one path.

  /** Sentinel path cost meaning "unreachable" that this node advertises. */
  public static final long UNREACHABLE = 1_000_000_000L;

  /**
   * Any advertised cost at or above this is treated as unreachable on receipt.
   * Equal to {@link #UNREACHABLE} by specification (protocol.md &sect;0), so a
   * saturated sum is indistinguishable from an explicit poison.
   *
   * <p>This port used to advertise {@code Long.MAX_VALUE} and interoperated only by
   * luck of the tolerant threshold. That is not safe luck: 2^63-1 exceeds the
   * largest integer a double represents exactly, so a JSON parser backed by doubles
   * reads it back as a different number. Real path costs (summed millisecond
   * latencies) never approach 1e9.</p>
   */
  public static final long POISON_THRESHOLD = 1_000_000_000L;

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
    neighbors.computeIfAbsent(key(label), k -> new LatencyTracker()).update(rttSampleMillis);
  }

  /**
   * Removes a neighbor and withdraws every route that went through it (defect
   * D4's converse: a dead neighbor's routes are poisoned, not left stale).
   *
   * @param label the neighbor's label
   */
  public synchronized void removeNeighbor(String label) {
    neighbors.remove(key(label));
    routes.entrySet().removeIf(e -> e.getValue().via.equals(key(label)));
  }

  /** @return the measured latency to a direct neighbor, or MAX_VALUE if unknown */
  public synchronized long neighborLatency(String label) {
    LatencyTracker t = neighbors.get(key(label));
    return t == null ? UNREACHABLE : t.latencyMillis();
  }

  /** @return whether the label is a direct neighbor */
  public synchronized boolean isNeighbor(String label) {
    return neighbors.containsKey(key(label));
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
    // Fold both labels once, up front, and work in folded terms from there -- the way
    // the other six do. Storing an unfolded `via` made nextHop hand back whatever
    // casing the advertisement happened to use, which then travelled on to the links
    // map and into disco.routes.
    String d = key(dest);
    String v = key(viaNeighbor);
    if(d.equals(key(selfLabel))) return;     // never route to ourselves
    if(d.equals(v)) return;                  // that is just the neighbor itself
    if(!neighbors.containsKey(v)) return;    // only learn via known neighbors
    if(neighbors.containsKey(d)) return;     // a direct neighbor needs no routed path
    if(advertisedCost >= POISON_THRESHOLD) { // poisoned: withdraw if we used this via
      Route existing = routes.get(d);
      if(existing != null && existing.via.equals(v)) routes.remove(d);
      return;
    }
    long cost = saturatingSum(advertisedCost, neighborLatency(v));
    Route existing = routes.get(d);
    if(existing == null || existing.via.equals(v) || cost < existing.cost)
      routes.put(d, new Route(v, cost));
  }

  /**
   * Selects the next hop toward a destination: the destination itself if it is
   * a direct neighbor, otherwise the neighbor named by the best route.
   *
   * @param dest the destination label
   * @return the next-hop neighbor label, or {@code null} if unreachable
   */
  public synchronized String nextHop(String dest) {
    // Both maps are keyed by the folded label, so one lookup answers it. This used to
    // need a linear equalsIgnoreCase scan over the neighbors, because that map alone
    // was keyed by the label exactly as given -- see the class comment.
    if(neighbors.containsKey(key(dest))) return key(dest);
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
      if(e.getKey().equals(key(toNeighbor))) continue; // no need to tell them about themselves
      advert.put(e.getKey(), e.getValue().latencyMillis());
    }
    for(var e : routes.entrySet()) {
      Route r = e.getValue();
      long cost = r.via.equals(key(toNeighbor)) ? UNREACHABLE : r.cost; // poisoned reverse
      advert.put(e.getKey(), cost);
    }
    advert.remove(key(selfLabel));
    return advert;
  }

  /**
   * Adds two path costs, clamping anything at or past the poison threshold to
   * {@link #UNREACHABLE}.
   *
   * <p>This used to detect only arithmetic overflow and return
   * {@code Long.MAX_VALUE}, which the other six never did: they clamp at the
   * threshold. That mattered once the emitted sentinel became a pinned wire value,
   * because a stored cost is what {@link #advertiseTo} puts on the wire — so a
   * summed cost past the threshold would have been advertised as some arbitrary
   * number, or as 2^63-1, rather than as the pinned poison.</p>
   *
   * @param a the first cost
   * @param b the second cost
   * @return the sum, or {@link #UNREACHABLE} if either input or the sum is poisoned
   */
  private static long saturatingSum(long a, long b) {
    if(a >= POISON_THRESHOLD || b >= POISON_THRESHOLD) return UNREACHABLE;
    long sum = a + b;
    if(sum < a || sum >= POISON_THRESHOLD) return UNREACHABLE; // overflow, or poisoned
    return sum;
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
