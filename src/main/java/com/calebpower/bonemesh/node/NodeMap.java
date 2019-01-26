package com.calebpower.bonemesh.node;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class NodeMap { // purpose of this is to add concurrency to list of node-edge relations
  
  private Lock lock = new Lock();
  private Map<Node, ArrayList<Edge>> knownNodes = null;
  
  public NodeMap() {
    this.knownNodes = new ConcurrentHashMap<>();
  }
  
  public synchronized void lock() {
    synchronized(lock) {
      while(lock.locked) {
        try {
          lock.wait();
        } catch(InterruptedException e) { }
      }
      lock.locked = true;
    }
  }
  
  public synchronized void unlock() {
    synchronized(lock) {
      synchronized(this) {
        lock.locked = false;
        lock.notifyAll();
        notifyAll();
      }
    }
  }
  
  public synchronized boolean isUnlocked() {
    return !lock.locked;
  }
  
  public synchronized NodeMap sync(NodeMap nodeMap) { // wipes this object and copies data from provided NodeMap
    System.out.println("Provided NodeMap is " + (nodeMap == null ? "null." : "not null."));
    lock();
    nodeMap.lock();
    
    synchronized(knownNodes) {
      synchronized(nodeMap.knownNodes) {
        knownNodes.clear();
        for(Node node : nodeMap.knownNodes.keySet()) {
          if(!knownNodes.containsKey(node))
            knownNodes.put(node, new ArrayList<>());
          for(Edge edge : nodeMap.knownNodes.get(node)) {
            knownNodes.get(node).add(edge);
          }
        }
      }
    }
    
    nodeMap.unlock();
    unlock();
    return this;
  }
  
  public synchronized void update(Node node, Edge edge) {
    lock();
    
    synchronized(knownNodes) {
      if(!knownNodes.containsKey(node))
        knownNodes.put(node,  new ArrayList<>());
      List<Edge> edges = knownNodes.get(node);
      Edge knownEdge = null;
      for(Edge e : edges)
        if(edge.equals(e)) knownEdge = e;
      
      if(knownEdge == null) {
        
      } else if(knownEdge.getWeight() < 0
          || edge.getWeight() < knownEdge.getWeight()) {
        knownEdge.getNode().setUUID(edge.getUUID());
        knownEdge.getNode().setInformalName(edge.getInformalName());
        knownEdge.setWeight(edge.getWeight());
        // edges.remove(knownEdge);
        // edges.add(edge);
      }
    }
    
    unlock();
  }
  
  public Node getNode(UUID uuid) {
    synchronized(knownNodes) {
      for(Node node : knownNodes.keySet())
        if(node.equals(uuid)) return node;
    }
    
    return null;
  }
  
  public Set<Node> getNodes() {
    synchronized(knownNodes) {
      return knownNodes.keySet();
    }
  }
  
  public List<Edge> getEdges(Node node) {
    for(Node n : getNodes())
      if(node.equals(n))
        return knownNodes.get(n);
    return null;
  }
  
  private class Lock {
    private boolean locked = false;
  }
  
}
