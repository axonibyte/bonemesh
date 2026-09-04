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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
}
