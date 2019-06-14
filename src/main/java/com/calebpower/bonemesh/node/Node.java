package com.calebpower.bonemesh.node;

/**
 * A model of a node or server in the BoneMesh network.
 * 
 * @author Caleb L. Power
 */
public class Node {
  
  private int port = 0;
  private String label = null;
  private String ip = null;
  
  /**
   * Overloaded constructor.
   * 
   * @param label the name of the node
   * @param ip the node's IP address
   * @param port the node's listening port
   */
  public Node(String label, String ip, int port) {
    this.label = label;
    this.ip = ip;
    this.port = port;
  }
  
  /**
   * Retrieves the node's label.
   * 
   * @return the label
   */
  public String getLabel() {
    return label;
  }
  
  /**
   * Retrieves the node's IP address.
   * 
   * @return the IP address
   */
  public String getIP() {
    return ip;
  }
  
  /**
   * Retrieves a node's listening port number.
   * 
   * @return the port number
   */
  public int getPort() {
    return port;
  }
  
}
