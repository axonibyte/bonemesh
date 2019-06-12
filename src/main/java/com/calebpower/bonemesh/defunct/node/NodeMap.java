package com.calebpower.bonemesh.defunct.node;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

public class NodeMap { // purpose of this is to add concurrency to list of node-edge relations

  private Lock lock = new Lock();
  private Map<Node, CopyOnWriteArrayList<Edge>> knownNodes = null;
  private Node mainNode = null;
  
  public NodeMap() {
    this.knownNodes = new ConcurrentHashMap<>();
  }
  
  public NodeMap(Node mainNode) {
    this();
    this.mainNode = mainNode;
    this.knownNodes.put(mainNode, new CopyOnWriteArrayList<>());
  }
  
  public synchronized void lock() {
    synchronized(lock) {
      while(lock.locked) {
        try {
          lock.wait();
        } catch(InterruptedException e) {
          e.printStackTrace();
        }
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
    if(nodeMap.mainNode != null) mainNode = nodeMap.mainNode;
    
    synchronized(knownNodes) {
      synchronized(nodeMap.knownNodes) {
        //knownNodes.clear();
        for(Node node : nodeMap.knownNodes.keySet()) {
          Node foundNode = grab(node.getUUID());
          if(foundNode == null) {
            knownNodes.put(node, new CopyOnWriteArrayList<>());
            foundNode = node;
          }
          for(Edge edge : nodeMap.knownNodes.get(node)) {
            //knownNodes.get(knownNode).add(edge);
            Edge foundEdge = grab(foundNode.getUUID(), edge.getUUID());
            if(foundEdge == null)
              knownNodes.get(foundNode).add(edge);
          }
        }
      }
    }
    
    nodeMap.unlock();
    unlock();
    return this;
  }
  
  public void update(Edge edge) {
    update(null, edge);
  }
  
  public Node grab(UUID uuid) {
    for(Node node : getNodes()) {
      if(node.getUUID().compareTo(uuid) == 0)
        return node;
    }
    return null;
  }
  
  public Edge grab(UUID nodeUUID, UUID edgeUUID) {
    Node node = grab(nodeUUID);
    if(node != null) {
      for(Edge edge : knownNodes.get(node)) {
        if(edge.getUUID().compareTo(edgeUUID) == 0)
          return edge;
      }
    }
    return null;
  }
  
  public synchronized void update(Node node, Edge edge) {
    lock();
    
    Node knownNode = node == null ? mainNode : grab(node.getUUID());
    
    if(knownNode == null) {
      knownNode = node;
      knownNodes.put(knownNode, new CopyOnWriteArrayList<>());
    }
    
    if(knownNode.equals(edge.getNode())) {
      System.out.println("Not mapping node to itself.");
      unlock();
      return;
    }
    
    System.out.println("!!!!!!!!!!!! " + knownNode.getUUID().toString() + " -> " + edge.getUUID().toString());
    
    List<Edge> edges = knownNodes.get(knownNode);
    Edge knownEdge = null;
    for(Edge e : edges)
      if(edge.equals(e)) knownEdge = e;
    
    if(knownEdge == null) {
      knownEdge = edge;
      edges.add(knownEdge);
    } else if(knownEdge.getWeight() < 0
        || edge.getWeight() < knownEdge.getWeight()) {
      knownEdge.getNode().setUUID(edge.getUUID());
      knownEdge.getNode().setInformalName(edge.getInformalName());
      knownEdge.setWeight(edge.getWeight());
      // edges.remove(knownEdge);
      // edges.add(edge);
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
  
  public void remove(Node node) {
    Node foundNode = grab(node.getUUID());
    if(foundNode != null)
      knownNodes.remove(foundNode);
  }
  
  private class Lock {
    private boolean locked = false;
  }
  
}
