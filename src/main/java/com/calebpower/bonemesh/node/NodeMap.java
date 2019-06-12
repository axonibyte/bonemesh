package com.calebpower.bonemesh.node;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class NodeMap {
  
  private Map<Node, Boolean> nodes = null;
  
  public NodeMap() {
    this.nodes = new ConcurrentHashMap<>();
  }
  
  public void addOrReplaceNode(Node node, boolean alive) {
    removeNode(node);
    nodes.put(node, alive);
  }
  
  public void removeNode(Node node) {
    if(nodes.containsKey(node)) nodes.remove(node);
  }
  
  public void setNodeAlive(Node node, boolean alive) {
    if(nodes.containsKey(node))
      nodes.replace(node, alive);
    else addOrReplaceNode(node, alive);
  }
  
  public Node getNodeByLabel(String label) {
    for(Node node : nodes.keySet())
      if(node.getLabel().equalsIgnoreCase(label))
        return node;
    return null;
  }
  
  public Set<Node> getNodes() {
    return nodes.keySet();
  }
  
  public boolean isKnown(Node node) {
    return nodes.containsKey(node);
  }
  
  public boolean isAlive(Node node) {
    return nodes.containsKey(node) && nodes.get(node).booleanValue();
  }
  
}
