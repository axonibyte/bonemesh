package com.calebpower.bonemesh.node;

public class Node {
  
  private int port = 0;
  private String label = null;
  private String ip = null;
  
  public Node(String label, String ip, int port) {
    this.label = label;
    this.ip = ip;
    this.port = port;
  }
  
  public String getLabel() {
    return label;
  }
  
  public String getIP() {
    return ip;
  }
  
  public int getPort() {
    return port;
  }
  
}
