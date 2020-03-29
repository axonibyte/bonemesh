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

import java.util.AbstractMap.SimpleEntry;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A container for a list of all nodes.
 * Maintains the statuses of these nodes.
 * 
 * @author Caleb L. Power
 */
public class NodeMap {
  
  private AtomicLong discoveryTimestamp = null; // system time at last discovery ping
  private Map<Node, Long> nodes = null; // all known nodes and their last discovery response
  private Map<String, Entry<Node, Long>> routes = null; // the best nodes with which to reach an indirect node
  
  /**
   * Overloaded constructor.
   * 
   * @param label the label of this BoneMesh instance 
   */
  public NodeMap(String label) {
    this.discoveryTimestamp = new AtomicLong();
    this.nodes = new ConcurrentHashMap<>();
    this.routes = new ConcurrentHashMap<>();
  }
  
  /**
   * Adds or replaces a node in the map.
   * 
   * @param node the node to be added
   * @param alive <code>true</code> iff the node is alive
   */
  public void addOrReplaceNode(Node node, boolean alive) {
    removeNode(node);
    nodes.put(node, alive ? System.currentTimeMillis() - discoveryTimestamp.get() : Long.MAX_VALUE);
/*
 *       if(routes.containsKey(knownNode)) {
        if(routes.get(knownNode).getValue() > knownNodes.get(knownNode))
          routes.replace(knownNode, new SimpleEntry<>(node, knownNodes.get(knownNode)));
      } else if(getNodeByLabel(knownNode) == null) {
        routes.put(knownNode, new SimpleEntry<>(node, knownNodes.get(knownNode)));
      }
 */
    //if(routes.containsKey(key))
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
    if(nodes.containsKey(node)) {
      nodes.replace(node, alive ? System.currentTimeMillis() - discoveryTimestamp.get() : Long.MAX_VALUE);
    } else addOrReplaceNode(node, alive);
  }
  
  /**
   * Retrieves all known nodes and their relative latencies.
   * 
   * @return a map of node labels and their latencies
   */
  public Map<String, Long> getKnownNodes() {
    Map<String, Long> knownNodes = new HashMap<>();
    for(String route : routes.keySet())
      knownNodes.put(route, routes.get(route).getValue());
    for(Node node : nodes.keySet()) if(knownNodes.containsKey(node.getLabel())
        && knownNodes.get(node.getLabel()) >= nodes.get(node))
      knownNodes.replace(node.getLabel(), nodes.get(node));
    else if(!knownNodes.containsKey(node.getLabel()))
      knownNodes.put(node.getLabel(), nodes.get(node));
    return knownNodes;
  }
  
  /**
   * Sets the neighbors of a node.
   * 
   * @param label the name of the node
   * @param knownNodes the targets that the node knows about
   */
  public void setNodeNeighbors(String label, Map<String, Long> knownNodes) {
    Node node = getNodeByLabel(label);
    if(node == null) {
      return;
    }
    
    if(knownNodes == null) {
      Set<String> deadRoutes = new HashSet<>();
      for(String route : routes.keySet()) // for all routes
        if(routes.get(route).getKey().getLabel().equalsIgnoreCase(label)) // check if we're using this node for routing
          deadRoutes.add(route);
      for(String route : deadRoutes) routes.remove(route); // if so, remove it
    } else {
      for(String knownNode : knownNodes.keySet()) { // for each known nodes
        if(routes.containsKey(knownNode) // if we know about the route
            && (routes.get(knownNode).getKey().getLabel().equalsIgnoreCase(label) // if the last best route was through this node
              || routes.get(knownNode).getValue() > knownNodes.get(knownNode) + nodes.get(node))) // or it's a better value
            routes.replace(knownNode, new SimpleEntry<>(node, // replace the route
                knownNodes.get(knownNode) + nodes.get(node)));
        else if(!routes.containsKey(knownNode)) // if we didn't know about the route
          routes.put(knownNode, new SimpleEntry<>(node, knownNodes.get(knownNode))); // save it
      }
    }
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
   * Retrieves all directly-known nodes.
   * 
   * @return a set of all directly-known nodes.
   */
  public Set<Node> getDirectNodes() {
    return nodes.keySet();
  }
  
  /**
   * Retrieves the labels of all directly- and indirectly-known nodes.
   * 
   * @return a set of all known node labels
   */
  public Set<String> getAllKnownNodeLabels() {
    Set<String> nodes = new HashSet<>();
    synchronized(routes) {
      for(String node : routes.keySet())
        nodes.add(node);
    }
    
    return nodes;
  }
  
  /**
   * Retrieves all living nodes.
   * 
   * @return a map of all living nodes and their latencies
   */
  public Map<String, Long> getLivingNodes() {
    Map<String, Long> livingNodes = new HashMap<>();
    for(Node n : nodes.keySet())
      if(nodes.get(n) < Long.MAX_VALUE)
        livingNodes.put(n.getLabel(), nodes.get(n));
        //livingNodes.put(n.getLabel(), getLatency(n));
    return livingNodes;
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
    return nodes.containsKey(node) && nodes.get(node) > -1L;
  }
  
  /**
   * Bumps the discovery timestamp.
   */
  public void bumpDiscoveryTime() {
    discoveryTimestamp.set(System.currentTimeMillis());
  }
  
  /**
   * Retrieve a neighboring node that will eventually connect to
   * the specified target node.
   * 
   * @param label the label of the target node
   * @return a good Node if it exists, or <code>null</code> if it doesn't
   */
  public Node getNextBestNode(String label) {
    Node node = null;
    if(routes.containsKey(label)) node = routes.get(label).getKey();
    return node;
  }
  
}
