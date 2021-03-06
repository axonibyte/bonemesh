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

package com.axonibyte.bonemesh;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.json.JSONException;
import org.json.JSONObject;

import com.axonibyte.bonemesh.listener.AckListener;
import com.axonibyte.bonemesh.listener.DataListener;
import com.axonibyte.bonemesh.listener.LogListener;
import com.axonibyte.bonemesh.listener.cheap.CheapDataListener;
import com.axonibyte.bonemesh.listener.cheap.CheapLogListener;
import com.axonibyte.bonemesh.message.DiscoveryMessage;
import com.axonibyte.bonemesh.message.GenericMessage;
import com.axonibyte.bonemesh.node.Node;
import com.axonibyte.bonemesh.node.NodeMap;
import com.axonibyte.bonemesh.socket.Payload;
import com.axonibyte.bonemesh.socket.SocketClient;
import com.axonibyte.bonemesh.socket.SocketServer;

/**
 * Virtual point-to-point mesh network driver for Java.
 * 
 * @author Caleb L. Power
 */
public class BoneMesh implements AckListener {
  
  private Logger logger = null;
  private NodeMap nodeMap = null;
  private SocketClient socketClient = null;
  private SocketServer socketServer = null;
  private String instanceLabel = null;
  private Thread heartbeatThread = null;

  private BoneMesh(String label) {
    this.logger = new Logger();
    this.instanceLabel = label;
    this.nodeMap = new NodeMap(label);
    Heartbeat heartbeat = new Heartbeat();
    heartbeatThread = new Thread(heartbeat);
    heartbeatThread.setDaemon(true);
  }
    
  /**
   * Builds a BoneMesh instance
   * 
   * @param label the name of this instance
   * @param port the port to listen to
   * @return BoneMesh the new BoneMesh instance
   */
  public static BoneMesh build(String label, int port) {
    BoneMesh boneMesh = new BoneMesh(label);
    boneMesh.socketClient = SocketClient.build(boneMesh, boneMesh.logger);
    boneMesh.socketServer = SocketServer.build(boneMesh, boneMesh.logger, port);
    boneMesh.heartbeatThread.start();
    return boneMesh;
  }
  
  /**
   * Test driver implementation.
   * Not to be used when implemented as a library.
   * 
   * @param args command-line arguments
   * @throws Exception to be thrown if something bad happens
   */
  public static void main(String[] args) throws Exception {
    Options options = new Options(); // start defining options
    options.addOption("h", "help", false, "Displays a friendly help message.");
    options.addOption("l", "node_label", true, "Node label.");
    options.addOption("p", "listening_port", true, "Server listening port.");
    Option targetNodesOption = new Option("t", "target_nodes", true, "Target nodes.");
    targetNodesOption.setArgs(Option.UNLIMITED_VALUES);
    targetNodesOption.setValueSeparator(',');
    options.addOption(targetNodesOption);
    CommandLineParser parser = new DefaultParser();
    CommandLine cmd = parser.parse(options, args);
    if(cmd.hasOption("help")) {
      System.out.println("BoneMesh: From Axonibyte Innovations, LLC.");
      System.out.println("Designed and Developed by Caleb L. Power");
      for(Option option : options.getOptions()) // TODO prettify this
        System.out.println(String.format("%1$s | %2$s\t%3$s",
            option.getLongOpt(),
            option.getOpt(),
            option.getDescription()));
    } else { // bad command args
      if(!cmd.hasOption("node_label")) throw new Exception("Missing label.");
      if(!cmd.hasOption("listening_port")) throw new Exception ("Missing listening port.");
      BoneMesh boneMesh = BoneMesh.build(
          cmd.getOptionValue("node_label"),
          Integer.parseInt(cmd.getOptionValue("listening_port")));
      
      boneMesh.logger.addListener(new CheapLogListener());
      
      if(cmd.hasOption("target_nodes")) {
        String[] targetNodes = cmd.getOptionValues("target_nodes");
        for(String targetNode : targetNodes) {
          String[] nodeArgs = targetNode.split("=");
          boneMesh.addNode(nodeArgs[0], nodeArgs[1]);
        }
      }
      
      boneMesh.logger.logInfo("BONEMESH", "Prompt is ready.");
      
      DataListener listener = new CheapDataListener(boneMesh.logger);
      boneMesh.addDataListener(listener);
      Scanner scanner = new Scanner(System.in);
      String line = null;
      while((line = scanner.nextLine()) != null && line.length() != 0) {
        try {
          if(line.startsWith("to:")) {
            String target = line.substring(3, line.indexOf(' '));
            boneMesh.sendDatum(target, new JSONObject()
                .put("line", line.substring(line.indexOf(' ') + 1)));
            continue;
          }
        } catch(Exception e) {
          e.printStackTrace();
        }
        boneMesh.broadcastDatum(new JSONObject().put("line", line));
      }
      scanner.close();
      boneMesh.kill();
      boneMesh.logger.logInfo("BONEMESH", "Goodbye! :)");
    }
  }
  
  /**
   * Adds a node to the BoneMesh network.
   * 
   * @param label the name of the server to be added
   * @param address the address of the server, i.e. <code>127.0.0.1:8888</code>
   * @throws Exception to be thrown if something bad happens
   */
  public void addNode(String label, String address) throws Exception { // this is a synchronous (blocking) method
    if(label == null) throw new Exception("Node label cannot be null.");
    if(address == null) throw new Exception("Node address cannot be null.");
    String[] splitAddress = address.split(":");
    if(splitAddress.length != 2) throw new Exception("Invalid node address.");
    int port = Integer.parseInt(splitAddress[1]);
    Node node = new Node(label, splitAddress[0], port);
    nodeMap.addOrReplaceNode(node, false);
    DiscoveryMessage message = new DiscoveryMessage(instanceLabel,
        label,
        nodeMap.getKnownNodes(),
        socketServer.getPort());
    Payload payload = new Payload(message, node.getLabel(), this, false);
    socketClient.queuePayload(payload);
  }
  
  /**
   * Removes a node from the BoneMesh network.
   * 
   * @param label the name of the server to be removed
   */
  public void removeNode(String label) {
    Node node = nodeMap.getNodeByLabel(label);
    if(node != null) nodeMap.removeNode(node);
  }
  
  /**
   * Broadcasts data to the entire network.
   * 
   * @param datum the datum to be broadcasted
   * @return <code>true</code> if broadcasting was successful
   */
  public boolean broadcastDatum(JSONObject datum) {
    return broadcastDatum(datum, true);
  }
  
  /**
   * Broadcasts data to the entire network.
   * 
   * @param datum the datum to be broadcasted
   * @param retryOnFailure resent the payload if there is a network error
   * @return <code>true</code> if broadcasting was successful
   */
  public boolean broadcastDatum(JSONObject datum, boolean retryOnFailure) {
    boolean success = true;
    for(String node : nodeMap.getAllKnownNodeLabels()) 
      success = sendDatum(node, datum, retryOnFailure) && success;
    return success;
  }
  
  /**
   * Sends data to a target server.
   * 
   * @param target the recipient server
   * @param datum the datum to be sent
   * @return <code>true</code> if the payload was queued;
   *         <code>false</code> is not an indicator of message reception
   */
  public boolean sendDatum(String target, JSONObject datum) {
    return sendDatum(target, datum, (AckListener[])null);
  }
    
  /**
   * Sends data to a target server.
   * 
   * @param target the recipient server
   * @param datum the datum to be sent
   * @param ackListeners additional listeners
   * @return <code>true</code> if the payload was queued;
   *         <code>false</code> is not an indicator of message reception
   */
  public boolean sendDatum(String target, JSONObject datum, AckListener... ackListeners) {
    return sendDatum(target, datum, true, ackListeners);
  }
  
  /**
   * Sends data to a target server.
   * 
   * @param target the recipient server
   * @param datum the datum to be sent
   * @param retryOnFailure repeat the request if there is a network failure
   * @return <code>true</code> if the payload was queued;
   *         <code>false</code> is not an indicator of message reception
   */
  public boolean sendDatum(String target, JSONObject datum, boolean retryOnFailure) {
    return sendDatum(target, datum, retryOnFailure, (AckListener[])null);
  }
  
  /**
   * Sends data to a target server.
   * 
   * @param target the recipient server
   * @param datum the datum to be sent
   * @param ackListeners additional listeners
   * @param retryOnFailure repeat the request if there is a network failure
   * @return <code>true</code> if the payload was queued;
   *         <code>false</code> is not an indicator of message reception
   */
  public boolean sendDatum(String target, JSONObject datum, boolean retryOnFailure, AckListener... ackListeners) {
    Node node = nodeMap.getNodeByLabel(target);
    if(node == null) { // try the next best thing if the first try didn't work
      node = nodeMap.getNextBestNode(target);
      if(node == null) return false;
    }
    GenericMessage message = new GenericMessage(instanceLabel, target, datum);
    List<AckListener> ackListenerArray = new ArrayList<>();
    ackListenerArray.add(this);
    if(ackListeners != null)
      for(AckListener listener : ackListeners)
        ackListenerArray.add(listener);
    Payload payload = new Payload(message, node.getLabel(), ackListenerArray, retryOnFailure);
    socketClient.queuePayload(payload);
    return true;
  }
  
  /**
   * Send a GenericMessage to a particular node. Generally used to transport
   * messages from other nodes.
   * 
   * @param message the generic message
   * @return <code>true</code> iff the payload was queued
   */
  public boolean sendDatum(GenericMessage message) {
    Node node = nodeMap.getNodeByLabel(message.getTo());
    if(node == null) {
      node = nodeMap.getNextBestNode(message.getTo());
      if(node == null) return false;
    }
    List<AckListener> ackListenerArray = new ArrayList<>();
    ackListenerArray.add(this);
    Payload payload = new Payload(message, node.getLabel(), ackListenerArray, false);
    socketClient.queuePayload(payload);
    return true;
  }
  
  private void setNodeStatus(Payload payload, boolean alive) {
    try {
      String target = payload.getData().getString("to");
      Node node = nodeMap.getNodeByLabel(target);
      boolean wasAlive = false;
      if(node != null) {
        wasAlive = nodeMap.isAlive(node);
        nodeMap.setNodeAlive(node, alive);
      }
      String message = String.format("Node %1$s is %2$s!", target, alive ? "ALIVE" : "DEAD");
      if(!wasAlive && alive) logger.logInfo("BONEMESH", message);
      else if(!alive) logger.logError("BONEMESH", message);
    } catch(JSONException e) {
      logger.logError("BONEMESH", e.getMessage());
    }
  }

  /**
   * Retrieves this label of this instance.
   * 
   * @return the label denoting this instance
   */
  public String getInstanceLabel() {
    return instanceLabel;
  }
  
  /**
   * Adds a data listener for data reception.
   * 
   * @param listener the data listener
   */
  public void addDataListener(DataListener listener) {
    socketServer.addDataListener(listener);
  }
  
  /**
   * Removes a data listener from the BoneMesh instance.
   * 
   * @param listener the data listener
   */
  public void removeDataListener(DataListener listener) {
    socketServer.removeDataListener(listener);
  }
  
  /**
   * Adds a log listener for log reception.
   * 
   * @param listener the log listener
   */
  public void addLogListener(LogListener listener) {
    logger.addListener(listener);
  }
  
  /**
   * Removes a log listener from the BoneMesh logger instance.
   * 
   * @param listener the log listener
   */
  public void removeLogListener(LogListener listener) {
    logger.removeListener(listener);
  }
  
  /**
   * Retrieves the node map.
   * 
   * @return the NodeMap instance
   */
  public NodeMap getNodeMap() {
    return nodeMap;
  }
  
  /**
   * Kills this BoneMesh node.
   */
  public void kill() {
    heartbeatThread.interrupt();
    socketClient.kill();
    socketServer.kill();
  }
  
  /**
   * {@inheritDoc}
   */
  @Override public void receiveAck(Payload payload) {
    setNodeStatus(payload, true);
  }

  /**
   * {@inheritDoc}
   */
  @Override public void receiveNak(Payload payload) {
    setNodeStatus(payload, false);
  }
  
  private class Heartbeat implements Runnable {
    @Override public void run() {
      try {
        for(;;) {
          Thread.sleep(5000L);
          Map<String, Long> nodes = nodeMap.getKnownNodes();
          nodeMap.bumpDiscoveryTime();
          for(Node node : nodeMap.getDirectNodes()) {
            DiscoveryMessage message = new DiscoveryMessage(instanceLabel,
                node.getLabel(),
                nodes,
                socketServer.getPort());
            Payload payload = new Payload(message, node.getLabel(), BoneMesh.this, false);
            socketClient.queuePayload(payload);
          }
        }
      } catch(InterruptedException e) { }
    }
  }
  
}
