package com.calebpower.bonemesh.node;

import java.util.UUID;

public class Edge {
  
  private Node node = null;
  private Long weight = null;
  
  public Edge(Node node) {
    this.node = null;
  }
  
  public Node getNode() {
    return node;
  }

  public UUID getUUID() {
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
    return weight;
  }
  
  public Edge setWeight(long weight) {
    this.weight = weight;
    return this;
  }
  
  public boolean equals(Edge edge) {
    return node.equals(edge.node);
  }
  
}
