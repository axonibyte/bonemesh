/*
 * Copyright (c) 2019 Axonibyte Innovations, LLC. All rights reserved.
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

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A container for a list of all nodes.
 * Maintains the statuses of these nodes.
 * 
 * @author Caleb L. Power
 */
public class NodeMap {
  
  private Map<Node, Boolean> nodes = null;
  
  /**
   * Null constructor.
   */
  public NodeMap() {
    this.nodes = new ConcurrentHashMap<>();
  }
  
  /**
   * Adds or replaces a node in the map.
   * 
   * @param node the node to be added
   * @param alive <code>true</code> if the node is alive
   */
  public void addOrReplaceNode(Node node, boolean alive) {
    removeNode(node);
    nodes.put(node, alive);
  }
  
  /**
   * Removes a node from the map, if it exists.
   * The node will not be in the map upon return.
   * 
   * @param node the node to be removed
   */
  public void removeNode(Node node) {
    if(nodes.containsKey(node)) nodes.remove(node);
  }
  
  /**
   * Sets a node as alive or dead.
   * If the node doesn't exist in the map, it gets added.
   * 
   * @param node the node
   * @param alive <code>true</code> if the node is alive
   */
  public void setNodeAlive(Node node, boolean alive) {
    if(nodes.containsKey(node))
      nodes.replace(node, alive);
    else addOrReplaceNode(node, alive);
  }
  
  /**
   * Retrieves a node by its label, if it exists.
   * 
   * @param label the name of the node
   * @return the matching node or <code>null</code> if it is isn't in the map
   */
  public Node getNodeByLabel(String label) {
    for(Node node : nodes.keySet())
      if(node.getLabel().equalsIgnoreCase(label))
        return node;
    return null;
  }
  
  /**
   * Retrieves all known nodes.
   * 
   * @return a set of all nodes.
   */
  public Set<Node> getNodes() {
    return nodes.keySet();
  }
  
  /**
   * Determines if a particular node is known.
   * 
   * @param node the node to check
   * @return <code>true</code> if the node is in this map
   */
  public boolean isKnown(Node node) {
    return nodes.containsKey(node);
  }
  
  /**
   * Determines if a particular node is both known and alive.
   * 
   * @param node the node to check
   * @return <code>true</code> if the node is in the map and is alive
   */
  public boolean isAlive(Node node) {
    return nodes.containsKey(node) && nodes.get(node).booleanValue();
  }
  
}