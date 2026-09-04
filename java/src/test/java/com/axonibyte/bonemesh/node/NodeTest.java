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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for the {@link Node} identity contract.
 *
 * A node's identity is its label, case-insensitively -- the same rule
 * {@link NodeMap#getNodeByLabel(String)} has always applied. Address and port
 * are mutable attributes, not identity.
 */
public class NodeTest {

  // Defect D2: Node is used as a map key, so equal labels must mean equal
  // nodes regardless of address, or one label accumulates duplicate entries.
  @Test void nodesWithSameLabelAreEqual() {
    assertEquals(new Node("a", "10.0.0.1", 1), new Node("a", "10.0.0.2", 2));
  }

  @Test void labelEqualityIsCaseInsensitive() {
    assertEquals(new Node("Alpha", "10.0.0.1", 1), new Node("aLPHA", "10.0.0.1", 1));
  }

  @Test void nodesWithDifferentLabelsAreNotEqual() {
    assertNotEquals(new Node("a", "10.0.0.1", 1), new Node("b", "10.0.0.1", 1));
  }

  @Test void equalNodesShareAHashCode() {
    assertEquals(new Node("Alpha", "10.0.0.1", 1).hashCode(),
        new Node("aLPHA", "10.0.0.2", 2).hashCode());
  }

  @Test void equalityIgnoresAddressMutation() {
    Node a = new Node("a", "10.0.0.1", 1);
    Node b = new Node("a", "10.0.0.1", 1);
    a.setIP("10.9.9.9").setPort(999);
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
  }

  @Test void nodeNeverEqualsNonNode() {
    assertNotEquals(new Node("a", "10.0.0.1", 1), "a");
    assertTrue(!new Node("a", "10.0.0.1", 1).equals(null));
  }
}
