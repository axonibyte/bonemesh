/*
 * Copyright (c) 2019 Axonibyte Innovations, LLC. All rights reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.axonibyte.bonemesh.node;

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
