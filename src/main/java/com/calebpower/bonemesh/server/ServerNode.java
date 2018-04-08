package com.calebpower.bonemesh.server;

public class ServerNode {
  
  private boolean eavesdrop = false;
  private int deathCount = 0;
  private int port = -1;
  private String externalHost = null;
  private String internalHost = null;
  private String name = null;
  private SubnetPreference subnetPreference = null;
  
  public static enum SubnetPreference {
    UNKNOWN,
    LOCAL,
    INTERNAL,
    EXTERNAL
  }
  
  public ServerNode(String name, String externalHost, String internalHost,
      int port, boolean eavesdrop) {
    this.name = name;
    this.externalHost = externalHost;
    this.internalHost = internalHost;
    this.port = port;
    this.eavesdrop = eavesdrop;
    this.subnetPreference = SubnetPreference.UNKNOWN;
    System.out.println("Createing node at " + (name == null ? "NULL" : name) + " " + externalHost + " " + internalHost + " " + port);
  }
  
  public boolean isAlive() {
    return deathCount == 0;
  }
  
  public void setAlive(boolean alive) {
    if(deathCount == 0 != alive)
      System.out.println("Node " + name + " is now " + (alive ? "alive" : "dead") + ".");
    deathCount = alive ? 0 : deathCount + 1;
  }
  
  public boolean isEavesdroppingEnabled() {
    return eavesdrop;
  }
  
  public String getName() {
    return name;
  }
  
  public String getExternalHost() {
    return externalHost;
  }
  
  public String getInternalHost() {
    return internalHost;
  }
  
  public int getPort() {
    return port;
  }
  
  public SubnetPreference getSubnetPreference() {
    return subnetPreference;
  }
  
  public void setSubnetPreference(SubnetPreference subnetPreference) {
    this.subnetPreference = subnetPreference;
  }
}
