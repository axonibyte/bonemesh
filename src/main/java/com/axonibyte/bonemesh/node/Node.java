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

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A model of a node or server in the BoneMesh network.
 * 
 * @author Caleb L. Power
 */
public class Node {
  
  private AtomicReference<String> label = null;
  private AtomicReference<String> ip = null;
  private AtomicInteger port = null;
  
  /**
   * Overloaded constructor.
   * 
   * @param label the name of the node
   * @param ip the node's IP address
   * @param port the node's listening port
   */
  public Node(String label, String ip, int port) {
    this.label = new AtomicReference<>(label);
    this.ip = new AtomicReference<>(ip.startsWith("/") ? ip.substring(1) : ip);
    this.port = new AtomicInteger(port);
  }
  
  /**
   * Retrieves the node's label.
   * 
   * @return the label
   */
  public String getLabel() {
    return label.get();
  }
  
  /**
   * Sets the node's label.
   * 
   * @param label the label
   * @return this Node object
   */
  public Node setLabel(String label) {
    this.label.set(label);
    return this;
  }
  
  /**
   * Retrieves the node's IP address.
   * 
   * @return the IP address
   */
  public String getIP() {
    return ip.get();
  }
  
  /**
   * Sets the node's IP address.
   * 
   * @param ip the IP address
   * @return this Node object
   */
  public Node setIP(String ip) {
    this.ip.set(ip.startsWith("/") ? ip.substring(1) : ip);
    return this;
  }
  
  /**
   * Retrieves the node's listening port number.
   * 
   * @return the port number
   */
  public int getPort() {
    return port.get();
  }
  
  /**
   * Sets the node's listening port number.
   * 
   * @param port the port number
   * @return this Node object
   */
  public Node setPort(int port) {
    this.port.set(port);
    return this;
  }
  
}
