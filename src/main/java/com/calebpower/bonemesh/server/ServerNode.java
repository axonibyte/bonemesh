package com.calebpower.bonemesh.server;

public class ServerNode {
  
  private boolean alive = false;
  private boolean eavesdrop = false;
  private int port = -1;
  private String externalHost = null;
  private String internalHost = null;
  private String name = null;
  private SubnetPreference subnetPreference = null;
  
  public static enum SubnetPreference {
    UNKNOWN,
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
  }
  
  public boolean isAlive() {
    return alive;
  }
  
  public void setAlive(boolean alive) {
    this.alive = alive;
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
