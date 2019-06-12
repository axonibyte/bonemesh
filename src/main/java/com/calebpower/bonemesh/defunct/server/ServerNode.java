package com.calebpower.bonemesh.defunct.server;

import com.calebpower.bonemesh.defunct.BoneMeshOld;

/**
 * Representation of a BoneMeshOld server node on the network.
 * 
 * @author Caleb L. Power
 */
public class ServerNode {
  
  private BoneMeshOld boneMesh = null;
  private boolean eavesdrop = false;
  private boolean master = false;
  private int deathCount = 0;
  private int port = -1;
  private String externalHost = null;
  private String internalHost = null;
  private String name = null;
  private SubnetPreference subnetPreference = SubnetPreference.UNKNOWN;
  
  /**
   * The subnet preference, on a general level.
   * 
   * @author Caleb L. Power
   */
  public static enum SubnetPreference {
    /**
     * Unknown IP location (either due to a new or invalid node)
     */
    UNKNOWN,
    
    /**
     * Local host (127.0.0.1)
     */
    LOCAL,
    
    /**
     * Internal IP (not local host, just within the intranet)
     */
    INTERNAL,
    
    /**
     * External IP, outside of the intranet
     */
    EXTERNAL
  }
  
  /**
   * Overloaded constructor to instantiate a BoneMeshOld server node.
   * 
   * @param boneMesh BoneMeshOld instance
   * @param name the name of the server node
   * @param externalHost the node's external host (internet)
   * @param internalHost the node's internal host (intranet)
   * @param port the node's listening port
   * @param eavesdrop <code>true</code> to eavesdrop,
   *                  <code>false</code> to not eavesdrop //XXX deprecated
   */
  public ServerNode(BoneMeshOld boneMesh, String name, String externalHost,
      String internalHost, int port, boolean eavesdrop) {
    this.boneMesh = boneMesh;
    this.name = name;
    this.externalHost = externalHost;
    this.internalHost = internalHost;
    this.port = port;
    this.eavesdrop = eavesdrop;
    this.subnetPreference = SubnetPreference.UNKNOWN;
    this.master = boneMesh.isMaster(externalHost,  internalHost, port);
    
    boneMesh.log("Creating node at " + (name == null ? "NULL" : name) + " " + externalHost + " " + internalHost + " " + port);
  }
  
  /**
   * Checks to see if the node is alive on the network.
   * 
   * @return <code>true</code> if the node is alive or
   *         <code>false</code> if the node is dead
   */
  public boolean isAlive() {
    return deathCount == 0;
  }
  
  /**
   * Updates the status of the server node as either dead or alive.
   * 
   * @param alive <code>true</code> if the node is alive or
   *              <code>false</code> if the node is dead
   */
  public void setAlive(boolean alive) {
    if(deathCount == 0 != alive)
      boneMesh.log("Node " + name + " is now " + (alive ? "alive" : "dead") + ".");
    deathCount = alive ? 0 : deathCount + 1;
  }
  
  /**
   * Checks to see if eavesdropping is enabled.
   * 
   * @return <code>true</code> if eavesdropping is enabled or
   *         <code>false</code> if eavesdropping is not enabled
   */
  public boolean isEavesdroppingEnabled() { //XXX this really should refer to a eavesdropping plugin, not an eavesdropping node
    return eavesdrop;
  }
  
  /**
   * Checks to see whether or not this node is a master node.
   * 
   * @return <code>true</code> if this node is a master node or
   *         <code>false</code> if this node is not a master node
   */
  public boolean isMaster() {
    return master;
  }
  
  /**
   * Sets or unsets the master status of a particular node.
   * 
   * @param master <code>true</code> if this node should be a master node or
   *               <code>false</code> if this node should not be a master node
   * @return ServerNode this node
   */
  public ServerNode setMaster(boolean master) {
    this.master = master;
    return this;
  }
  
  /**
   * Retrieves the name of the server node.
   * 
   * @return String representation of the node's name
   */
  public String getName() {
    return name;
  }
  
  /**
   * Retrieves the external IP of the server node.
   * 
   * @return String representation of the node's external IP
   */
  public String getExternalHost() {
    return externalHost;
  }
  
  /**
   * Retrieves the internal IP of the server node.
   * 
   * @return String representation of the node's internal IP
   */
  public String getInternalHost() {
    return internalHost;
  }
  
  /**
   * Retrieves the listening port of the server node.
   * 
   * @return int representation of the node's listening port
   */
  public int getPort() {
    return port;
  }
  
  /**
   * Sets the known listening port of the server node in question.
   * Does not actually change the listening port on the node itself.
   * 
   * @param port the node's listening port
   * @return ServerNode this node
   */
  public ServerNode setPort(int port) {
    this.port = port;
    return this;
  }
  
  /**
   * Retrieves the subnet preference for this node.
   * 
   * @return SubnetPreference the appropriate subnet preference to use
   */
  public SubnetPreference getSubnetPreference() {
    return subnetPreference;
  }
  
  /**
   * Sets the appropriate subnet preference for this node.
   * 
   * @param subnetPreference the appropriate subnet preference to use
   * @return ServerNode this node
   */
  public ServerNode setSubnetPreference(SubnetPreference subnetPreference) {
    this.subnetPreference = subnetPreference;
    return this;
  }
  
}
