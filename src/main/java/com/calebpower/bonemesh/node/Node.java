package com.calebpower.bonemesh.node;

import java.util.UUID;

import com.calebpower.bonemesh.socket.IncomingDataHandler;

public class Node {
  
  private int port = 0;
  private IncomingDataHandler incomingDataHandler = null;
  private String informalName = null;
  private String ip = null;
  private UUID uuid = null;
  
  public UUID getUUID() {
    return uuid;
  }
  
  public Node setUUID(UUID uuid) {
    this.uuid = uuid;
    return this;
  }
  
  public Node setUUID(String uuid) { // TODO might need to add exception handling to this
    return setUUID(UUID.fromString(uuid)); 
  }
  
  public String getInformalName() {
    return informalName;
  }
  
  public Node setInformalName(String informalName) {
    this.informalName = informalName;
    return this;
  }
  
  public boolean equals(Node node) {
    return node != null && node.uuid != null && uuid.compareTo(node.uuid) == 0;
  }
  
  public boolean equals(UUID uuid) {
    return uuid.compareTo(uuid) == 0;
  }
  
  public String getIP() {
    return ip;
  }
  
  public Node setIP(String ip) {
    this.ip = ip;
    return this;
  }
  
  public int getPort() {
    return port;
  }
  
  public Node setPort(int port) {
    this.port = port;
    return this;
  }
  
  public boolean isStale() {
    return incomingDataHandler != null && incomingDataHandler.isStale();
  }
  
  public boolean isDead() {
    return incomingDataHandler != null && incomingDataHandler.isDead();
  }
  
  public void touch() {
    if(incomingDataHandler != null) incomingDataHandler.touch();
  }
  
  public void kill() {
    if(incomingDataHandler != null) incomingDataHandler.kill();
  }
  
  public IncomingDataHandler getIncomingDataHandler() {
    return incomingDataHandler;
  }
  
  public Node setIncomingDataHandler(IncomingDataHandler incomingDataHandler) {
    this.incomingDataHandler = incomingDataHandler;
    return this;
  }
  
}
