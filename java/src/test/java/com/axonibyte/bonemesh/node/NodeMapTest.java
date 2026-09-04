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

package com.axonibyte.bonemesh.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.AbstractMap.SimpleEntry;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Pure unit tests for {@link NodeMap} liveness accounting.
 *
 * These tests prove liveness bookkeeping only. They do not prove anything
 * about routing correctness under churn or concurrency; those claims belong
 * to the interop harnesses (see docs/PLAN.md).
 */
public class NodeMapTest {

  private NodeMap map;

  @BeforeEach void setUp() {
    map = new NodeMap("self", "self-pubkey");
  }

  // Defect D1: a dead node is recorded with a Long.MAX_VALUE latency
  // sentinel, and isAlive() must report it dead, not alive.
  @Test void deadNodeIsNotAlive() {
    Node node = new Node("peer", "127.0.0.1", 40000);
    map.setNode(node, false);
    assertTrue(map.isKnown(node));
    assertFalse(map.isAlive(node));
  }

  @Test void livingNodeIsAlive() {
    Node node = new Node("peer", "127.0.0.1", 40000);
    map.setNode(node, true);
    assertTrue(map.isAlive(node));
  }

  @Test void unknownNodeIsNotAlive() {
    assertFalse(map.isAlive(new Node("stranger", "127.0.0.1", 40000)));
  }

  @Test void nodeMarkedDeadThenAliveIsAlive() {
    Node node = new Node("peer", "127.0.0.1", 40000);
    map.setNode(node, false);
    map.setNode(node, true);
    assertTrue(map.isAlive(node));
  }

  // isAlive and getLivingNodes are two oracles over the same sentinel; they
  // must agree in both directions.
  @Test void livingNodesAgreesWithIsAlive() {
    Node dead = new Node("dead", "127.0.0.1", 40000);
    Node live = new Node("live", "127.0.0.1", 40001);
    map.setNode(dead, false);
    map.setNode(live, true);
    assertFalse(map.getLivingNodes().containsKey("dead"));
    assertTrue(map.getLivingNodes().containsKey("live"));
    assertFalse(map.isAlive(dead));
    assertTrue(map.isAlive(live));
  }

  @Test void removedNodeIsUnknownAndNotAlive() {
    Node node = new Node("peer", "127.0.0.1", 40000);
    map.setNode(node, true);
    map.removeNode(node);
    assertFalse(map.isKnown(node));
    assertFalse(map.isAlive(node));
    assertNull(map.getNodeByLabel("peer"));
  }

  @Test void getNodeByLabelIsCaseInsensitive() {
    Node node = new Node("Peer", "127.0.0.1", 40000);
    map.setNode(node, true);
    assertSame(node, map.getNodeByLabel("pEEr"));
  }

  @Test void selfPubkeyIsRecordedAtConstruction() {
    assertEquals("self-pubkey", map.getPubkey("self"));
  }

  // Defect D2: re-adding a label must replace the entry, not accumulate a
  // duplicate. The replacement's address wins.
  @Test void reAddingALabelReplacesTheEntry() {
    map.setNode(new Node("peer", "10.0.0.1", 40000), true);
    map.setNode(new Node("peer", "10.0.0.2", 40001), true);
    assertEquals(1, map.getDirectNodes().size());
    assertEquals("10.0.0.2", map.getNodeByLabel("peer").getIP());
    assertEquals(40001, map.getNodeByLabel("peer").getPort());
  }

  @Test void reAddingALabelWithDifferentCaseReplacesTheEntry() {
    map.setNode(new Node("Peer", "10.0.0.1", 40000), true);
    map.setNode(new Node("pEEr", "10.0.0.2", 40001), true);
    assertEquals(1, map.getDirectNodes().size());
  }

  // Defect D5: a direct neighbor that no advertisement has mentioned yet must
  // still be a broadcast target.
  @Test void directNodesAppearInAllKnownLabels() {
    map.setNode(new Node("direct", "10.0.0.1", 40000), true);
    assertTrue(map.getAllKnownNodeLabels().contains("direct"));
  }

  @Test void routedNodesAppearInAllKnownLabels() {
    Node via = new Node("via", "10.0.0.1", 40000);
    map.setNode(via, true);
    map.setNodeNeighbors("via", Map.of("far", new SimpleEntry<>("far-pubkey", 5L)));
    assertTrue(map.getAllKnownNodeLabels().contains("far"));
  }

  // Defect D5: neighbors advertise us back to ourselves; our own label must
  // never become a broadcast target or a route.
  @Test void ownLabelNeverAppearsInAllKnownLabels() {
    Node via = new Node("via", "10.0.0.1", 40000);
    map.setNode(via, true);
    map.setNodeNeighbors("via", Map.of(
        "self", new SimpleEntry<>("self-pubkey", 5L),
        "far", new SimpleEntry<>("far-pubkey", 5L)));
    assertFalse(map.getAllKnownNodeLabels().contains("self"));
    assertNull(map.getNextBestNode("self"));
  }

  // Defect D3 (guard only; the real fix is the v3 latency scheme): a dead
  // next hop has latency Long.MAX_VALUE, and adding an advertised latency to
  // it must saturate rather than overflow to a "best" negative route.
  @Test void routeLatencyThroughDeadNodeSaturatesInsteadOfOverflowing() {
    Node dead = new Node("deadvia", "10.0.0.1", 40000);
    map.setNode(dead, false);
    map.setNodeNeighbors("deadvia", Map.of("far", new SimpleEntry<>("far-pubkey", 5L)));
    Long advertised = map.getKnownNodes().get("far");
    assertNotNull(advertised);
    assertTrue(advertised >= 0L, "route latency overflowed to " + advertised);
  }

  @Test void nullNeighborsDropRoutesThroughThatNode() {
    Node via = new Node("via", "10.0.0.1", 40000);
    map.setNode(via, true);
    map.setNodeNeighbors("via", Map.of("far", new SimpleEntry<>("far-pubkey", 5L)));
    map.setNodeNeighbors("via", null);
    assertNull(map.getNextBestNode("far"));
  }
}
