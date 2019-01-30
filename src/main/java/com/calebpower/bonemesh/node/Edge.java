package com.calebpower.bonemesh.node;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

public class Edge {
  
  private Node node = null;
  private AtomicLong weight = null;
  
  public Edge(Node node) {
    this.node = node;
    this.weight = new AtomicLong();
  }
  
  public Node getNode() {
    return node;
  }

  public UUID getUUID() {
    if(node == null) System.out.println("Node is null.");
    if(node.getUUID() == null) System.out.println("UUID is null.");
    System.out.println(node.getUUID());
    return node.getUUID();
  }
  
  public Edge setUUID(UUID uuid) {
    node.setUUID(uuid);
    return this;
  }
  
  public Edge setUUID(String uuid) {
    node.setUUID(uuid);
    return this;
  }
  
  public String getInformalName() {
    return node.getInformalName();
  }
  
  public Edge setInformalName(String informalName) {
    node.setInformalName(informalName);
    return this;
  }
  
  public long getWeight() {
    return weight.get();
  }
  
  public Edge setWeight(long weight) {
    this.weight.set(weight);
    return this;
  }
  
  public boolean equals(Edge edge) {
    return edge != null
        && edge.node != null
        && node.equals(edge.node);
  }
  
}
