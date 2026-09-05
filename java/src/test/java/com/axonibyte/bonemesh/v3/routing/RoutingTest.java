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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import com.axonibyte.bonemesh.v3.routing.Router.Decision;

/**
 * Routing tests: real EWMA latency (D3), per-hop failure attribution (D4),
 * poisoned reverse, saturating cost, and ttl handling.
 */
public class RoutingTest {

  // --- LatencyTracker (defect D3: a real, smoothed duration) ---

  @Test void firstSampleSetsLatency() {
    LatencyTracker t = new LatencyTracker(0.2);
    t.update(100);
    assertEquals(100, t.latencyMillis());
  }

  @Test void ewmaSmoothsSamples() {
    LatencyTracker t = new LatencyTracker(0.2);
    t.update(100);
    t.update(200); // 0.2*200 + 0.8*100 = 120
    assertEquals(120, t.latencyMillis());
  }

  @Test void unknownLatencyIsMaxValue() {
    assertEquals(Long.MAX_VALUE, new LatencyTracker().latencyMillis());
  }

  // --- RoutingTable ---

  @Test void directNeighborIsItsOwnNextHop() {
    RoutingTable rt = new RoutingTable("self");
    rt.observeNeighbor("beta", 10);
    assertEquals("beta", rt.nextHop("beta"));
  }

  @Test void learnedRouteResolvesToTheAdvertisingNeighbor() {
    RoutingTable rt = new RoutingTable("self");
    rt.observeNeighbor("beta", 10);
    rt.learnRoute("delta", "beta", 5); // delta reachable via beta
    assertEquals("beta", rt.nextHop("delta"));
  }

  @Test void ownLabelIsNeverRouted() {
    RoutingTable rt = new RoutingTable("self");
    rt.observeNeighbor("beta", 10);
    rt.learnRoute("self", "beta", 1);
    assertNull(rt.nextHop("self"));
    assertTrue(rt.knownRouteDestinations().isEmpty());
  }

  @Test void betterRouteReplacesWorseOne() {
    RoutingTable rt = new RoutingTable("self");
    rt.observeNeighbor("beta", 100);
    rt.observeNeighbor("gamma", 1);
    rt.learnRoute("delta", "beta", 5);   // cost 105
    rt.learnRoute("delta", "gamma", 5);  // cost 6, better
    assertEquals("gamma", rt.nextHop("delta"));
  }

  @Test void deadNeighborWithdrawsItsRoutes() {
    RoutingTable rt = new RoutingTable("self");
    rt.observeNeighbor("beta", 10);
    rt.learnRoute("delta", "beta", 5);
    rt.removeNeighbor("beta");
    assertNull(rt.nextHop("delta"));
  }

  // Poisoned reverse: a route learned via beta is advertised back to beta as
  // unreachable, so a two-node loop cannot count to infinity.
  @Test void advertisementPoisonsRoutesBackToTheirSource() {
    RoutingTable rt = new RoutingTable("self");
    rt.observeNeighbor("beta", 10);
    rt.learnRoute("delta", "beta", 5);
    assertEquals(RoutingTable.UNREACHABLE, rt.advertiseTo("beta").get("delta"));
  }

  // A poisoned advert is recognized by threshold, not exact sentinel: Elixir and
  // the JS port poison with 1_000_000_000, not Long.MAX_VALUE. Without the
  // threshold check Java would install a bogus ~1e9-cost route and then
  // poison-reverse the destination back, flapping the route (observed against a
  // JS relay). It must withdraw, not install.
  @Test void tolerantPoisonThresholdWithdrawsAndInstallsNothing() {
    RoutingTable rt = new RoutingTable("self");
    rt.observeNeighbor("beta", 10);
    rt.learnRoute("delta", "beta", 5);
    rt.learnRoute("delta", "beta", 1_000_000_000L); // Elixir/JS poison sentinel
    assertNull(rt.nextHop("delta"), "a 1e9 poison from our next hop must withdraw the route");

    RoutingTable rt2 = new RoutingTable("self");
    rt2.observeNeighbor("beta", 10);
    rt2.learnRoute("gamma", "beta", 1_000_000_000L); // poison for a route we don't have
    assertNull(rt2.nextHop("gamma"), "a poison advert must never install a route");
  }

  // Cost arithmetic must saturate, never overflow negative through the sentinel.
  @Test void routeCostSaturatesInsteadOfOverflowing() {
    RoutingTable rt = new RoutingTable("self");
    rt.observeNeighbor("beta", 10);
    rt.learnRoute("delta", "beta", Long.MAX_VALUE - 1);
    Long advertised = rt.advertiseTo("gamma-unrelated").get("delta");
    assertTrue(advertised == null || advertised >= 0L, "cost overflowed: " + advertised);
  }

  // --- Router (defect D4: NAK names the failing hop, not the destination) ---

  @Test void deliversMessagesAddressedToSelf() {
    Router r = new Router("self", new RoutingTable("self"));
    Decision d = r.route(data("self", "alpha", 16));
    assertEquals(Decision.Action.DELIVER, d.action());
  }

  @Test void forwardDecrementsTtlAndTargetsTheNextHopNotTheDestination() {
    RoutingTable rt = new RoutingTable("self");
    rt.observeNeighbor("beta", 10);
    rt.learnRoute("delta", "beta", 5);
    Router r = new Router("self", rt);

    Decision d = r.route(data("delta", "alpha", 16));
    assertEquals(Decision.Action.FORWARD, d.action());
    // The hop a failure would be attributed to is beta (the next hop), not the
    // final destination delta -- this is the D4 fix.
    assertEquals("beta", d.nextHop());
    assertEquals(15, d.message().getInt("ttl"));
  }

  @Test void ttlExhaustionDropsTheMessage() {
    Router r = new Router("self", routableToDelta());
    Decision d = r.route(data("delta", "alpha", 1)); // 1 - 1 = 0
    assertEquals(Decision.Action.DROP_TTL, d.action());
  }

  @Test void unreachableDestinationIsReported() {
    Router r = new Router("self", new RoutingTable("self"));
    Decision d = r.route(data("nowhere", "alpha", 16));
    assertEquals(Decision.Action.UNREACHABLE, d.action());
  }

  private static RoutingTable routableToDelta() {
    RoutingTable rt = new RoutingTable("self");
    rt.observeNeighbor("beta", 10);
    rt.learnRoute("delta", "beta", 5);
    return rt;
  }

  private static JSONObject data(String to, String from, int ttl) {
    return new JSONObject().put("type", "data").put("mid", "0".repeat(32))
        .put("to", to).put("from", from).put("ttl", ttl).put("payload", new JSONObject());
  }
}
