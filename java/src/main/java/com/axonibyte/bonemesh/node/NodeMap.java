/*
 * Copyright (c) 2019-2023 Axonibyte Innovations, LLC. All rights reserved.
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

import com.axonibyte.bonemesh.BoneMesh;

import org.bouncycastle.util.encoders.Base64;

/**
 * A container for a list of all nodes.
 * Maintains the statuses of these nodes.
 * 
 * @author Caleb L. Power <cpower@axonibyte.com>
 */
public class NodeMap {

  private AtomicLong discoveryTimestamp = new AtomicLong(); // system time at last discovery ping
  private Map<Node, Long> nodes = new ConcurrentHashMap<>(); // all known nodes and their last discovery response
  private Map<String, Entry<Node, Long>> routes = new ConcurrentHashMap<>(); // the best nodes with which to reach an indirect node
  private Map<String, String> pubkeys = new ConcurrentHashMap<>(); // pubkeys and a confirmation indicator

  /**
   * Instantiates this {@link NodeMap} object.
   *
   * @param boneMesh the active {@link BoneMesh} object
   */
  public NodeMap(BoneMesh boneMesh) {
    /*
    nodes.put(
        new Node(
            boneMesh.getInstanceLabel(),
            "127.0.0.1",
            boneMesh.getSocketServer().getPort()),
        0L);
    */
    pubkeys.put(
        boneMesh.getInstanceLabel(),
        new String(
            Base64.encode(
                boneMesh.getCryptoEngine().getPubkey())));
  }

  /**
   * Sets a nodes status in the node map.
   *
   * @param node the node to be added or updated
   * @param alive {@code true} iff the node is alive
   */
  public void setNode(Node node, boolean alive) {
    nodes.put(node, alive ? System.currentTimeMillis() - discoveryTimestamp.get() : Long.MAX_VALUE);
  }
  
  /**
   * Removes a node from the map, if it exists.
   * The node will not be in the map upon return.
   * 
   * @param node the node to be removed
   */
  public void removeNode(Node node) {
    nodes.remove(node);
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
  public void setNodeNeighbors(String label, Map<String, Entry<String, Long>> knownNodes) {
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
      for(var knownNode : knownNodes.entrySet()) { // for each known nodes
        String knLabel = knownNode.getKey();
        String knPubkey = knownNode.getValue().getKey();
        Long knLatency = knownNode.getValue().getValue();
        if(routes.containsKey(knLabel) // if we know about the route
            && (routes.get(knLabel).getKey().getLabel().equalsIgnoreCase(label) // if the last best route was through this node
                || routes.get(knLabel).getValue() > knLatency + nodes.get(node))) // or it's a better value
          routes.replace( // replace the route
              knLabel,
              new SimpleEntry<>( // replace the route
                  node,
                  knLatency + nodes.get(node)));
        else if(!routes.containsKey(knLabel)) // if we didn't know about the route
          routes.put(knLabel, new SimpleEntry<>(node, knLatency + nodes.get(node))); // save it
        
        if(!pubkeys.containsKey(knLabel)) // save pubkey if we don't know about it
          pubkeys.put(knLabel, knPubkey);
        else if(!pubkeys.get(knLabel).equals(knPubkey) && !knPubkey.isBlank()) // or update it if it changed
          pubkeys.replace(knLabel, knPubkey);
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
   * Retrieves the public key associated with a {@link BoneMesh} node.
   *
   * @param label the name of the node
   * @return a String representation of the pubkey, or {@code null}
   *         if no pubkey was found to be associated with the node
   */
  public String getPubkey(String label) {
    return pubkeys.get(label);
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
   * Updates the pubkey associated with a node.
   *
   * @param node the node associated with the pubkey
   * @param pubkey the Base64-encoded String representatio of the pubkey
   */
  public void setPubkey(String node, String pubkey) {
    pubkeys.put(node, pubkey);
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
