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
import java.util.LinkedList;
import java.util.List;
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
  private Map<String, Map<String, Long>> neighbors = null; // all known nodes and their neighbors, by label
  private Map<String, Node> routes = null; // target nodes and best first-degree of routing
  private String thisLabel = null;
  
  /**
   * Overloaded constructor.
   * 
   * @param label the label of this BoneMesh instance 
   */
  public NodeMap(String label) {
    this.discoveryTimestamp = new AtomicLong();
    this.nodes = new ConcurrentHashMap<>();
    this.neighbors = new ConcurrentHashMap<>();
    this.routes = new HashMap<>();
    this.thisLabel = label;
  }
  
  /**
   * Adds or replaces a node in the map.
   * 
   * @param node the node to be added
   * @param alive <code>true</code> iff the node is alive
   * @param rework <code>true</code> to rework the node routes
   */
  public void addOrReplaceNode(Node node, boolean alive, boolean rework) {
    removeNode(node, false);
    nodes.put(node, alive ? System.currentTimeMillis() : -1L);
    if(rework) reworkRoutes();
  }
  
  /**
   * Removes a node from the map, if it exists.
   * The node will not be in the map upon return.
   * 
   * @param node the node to be removed
   * @param rework <code>true</code> to rework the node routes
   */
  public void removeNode(Node node, boolean rework) {
    if(nodes.containsKey(node)) nodes.remove(node);
    if(rework) reworkRoutes();
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
      nodes.replace(node, alive ? System.currentTimeMillis() : -1L);
    } else addOrReplaceNode(node, alive, false);
    reworkRoutes();
  }
  
  /**
   * Sets the neighbors of a node.
   * 
   * @param label the name of the node
   * @param neighbors the node's neighbors
   */
  public void setNodeNeighbors(String label, Map<String, Long> neighbors) {
    if(this.neighbors.containsKey(label))
      this.neighbors.replace(label, neighbors);
    else this.neighbors.put(label, neighbors);
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
      if(nodes.get(n) > -1L)
        livingNodes.put(n.getLabel(), getLatency(n));
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
   * Retrieves the latency of a particular node.
   * 
   * @param node the node in question
   * @return UNIX timestamp delta or <code>Long.MAX_VALUE</code> if the node
   *         doesn't exist or isn't alive 
   */
  public long getLatency(Node node) {
    return nodes.containsKey(node) && nodes.get(node) > -1L
        ? (nodes.get(node) - discoveryTimestamp.longValue()) : Long.MAX_VALUE;
  }
  
  /**
   * Retrieves the latency of a particular node by label.
   * 
   * @param label the name of the node in question
   * @return UNIX timestamp delta or <code>Long.MAX_VALUE</code> if the node
   *         doesn't exist or isn't alive
   */
  public long getLatency(String label) {
    for(Node n : nodes.keySet())
      if(n.getLabel().equalsIgnoreCase(label))
        return getLatency(n);
    return Long.MAX_VALUE;
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
    synchronized(routes) {
      if(routes.containsKey(label)) node = routes.get(label);
    }
    return node;
  }
  
  private synchronized void reworkRoutes() {
    System.out.println("!!!!!!!!!! 1");
    Map<String, Map<String, Long>> discoveredRoutes = new HashMap<>();
    for(String node : neighbors.keySet()) { // for every known node
      Map<String, Long> neighborhood = neighbors.get(node); // get a map of their neighbors
      
      for(String neighbor : neighborhood.keySet()) { // for every neighbor in the neighborhood
        if(!discoveredRoutes.containsKey(neighbor)) // if we don't already know about it
          discoveredRoutes.put(node, new HashMap<>()); // create an empty entry
        
        Node known = getNodeByLabel(neighbor); // see if they're our neighbor too
        if(known != null && !discoveredRoutes.get(neighbor).containsKey(thisLabel)) // and if they are
          discoveredRoutes.get(neighbor).put(thisLabel, nodes.get(known)); // add our distance
        
        // in any case, also get the distance in the actual neighborhood
        discoveredRoutes.get(neighbor).put(node, neighborhood.get(neighbor));
      }
    }
    
    System.out.println("!!!!!!!!!! 2");
    Map<String, Node> newRoutes = new HashMap<>();
    for(String target : discoveredRoutes.keySet()) { // iterate through each target
      // get the best route to this node
      Entry<String, Long> route = getBestRoute(discoveredRoutes, thisLabel, target, new LinkedList<>());
      if(route != null) { // if we get an answer
        Node best = getNodeByLabel(route.getKey()); // retrieve the actual node
        if(best != null) newRoutes.put(target, best); // save the node if it exists
      }
    }
    
    System.out.println("!!!!!!!!!! 4");
    synchronized(this.routes) { // save the results
      for(String target : newRoutes.keySet())
        this.routes.put(target, newRoutes.get(target));
    }
    
    System.out.println("!!!!!!!!!! 5");
  }
  
  private Entry<String, Long> getBestRoute(Map<String, Map<String, Long>> routes, String start, String target, List<String> seen) {
    System.out.println("!!!!!!!!!! 3");
    if(!routes.containsKey(target)) return null; // if the route doesn't contain the target, return null
    if(routes.get(target).containsKey(start)) // if the node has a direct link, return it 
      return new SimpleEntry<>(start, routes.get(target).get(start));
    Entry<String, Long> newRoute = null;
    seen.add(0, start); // make sure to not loop through the graph
    for(String neighbor : routes.keySet()) { // iterate through the neighbors
      Entry<String, Long> route = getBestRoute(routes, neighbor, start, seen); // recurse
      if(route != null) // do something if we get a result
        if(newRoute == null || route.getValue() < newRoute.getValue())
          newRoute = route; // save the lesser value
    }
    seen.remove(0); // make sure to pop the stack so we don't screw up other recursions
    return newRoute; // return the best route
  }
}
