package com.calebpower.bonemesh;

import java.util.Scanner;
import java.util.Set;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.json.JSONException;
import org.json.JSONObject;

import com.calebpower.bonemesh.listener.AckListener;
import com.calebpower.bonemesh.listener.DataListener;
import com.calebpower.bonemesh.listener.LogListener;
import com.calebpower.bonemesh.listener.cheap.CheapDataListener;
import com.calebpower.bonemesh.listener.cheap.CheapLogListener;
import com.calebpower.bonemesh.message.GenericMessage;
import com.calebpower.bonemesh.message.HelloMessage;
import com.calebpower.bonemesh.node.Node;
import com.calebpower.bonemesh.node.NodeMap;
import com.calebpower.bonemesh.socket.Payload;
import com.calebpower.bonemesh.socket.SocketClient;
import com.calebpower.bonemesh.socket.SocketServer;

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
  
  /**
   * Overloaded constructor.
   * 
   * @param label the name of this instance
   * @param port the port to listen to
   */
  public BoneMesh(String label, int port) {
    this.logger = new Logger();
    this.instanceLabel = label;
    this.nodeMap = new NodeMap();
    this.socketClient = SocketClient.build(logger);
    this.socketServer = SocketServer.build(logger, port);
    Heartbeat heartbeat = new Heartbeat();
    heartbeatThread = new Thread(heartbeat);
    heartbeatThread.setDaemon(true);
    heartbeatThread.start();
  }
  
  /**
   * Test driver implementation.
   * Not to be used when implemented as a library.
   * 
   * @param args command-line arguments
   * @throws Exception to be thrown if something bad happens
   */
  public static void main(String[] args) throws Exception {
    Options options = new Options();
    options.addOption("l", "node_label", true, "Node label.");
    options.addOption("p", "listening_port", true, "Server listening port.");
    Option targetNodesOption = new Option("t", "target_nodes", true, "Target nodes.");
    targetNodesOption.setArgs(Option.UNLIMITED_VALUES);
    targetNodesOption.setValueSeparator(',');
    options.addOption(targetNodesOption);
    CommandLineParser parser = new DefaultParser();
    CommandLine cmd = parser.parse(options, args);
    if(!cmd.hasOption("node_label")) throw new Exception("Missing label.");
    if(!cmd.hasOption("listening_port")) throw new Exception ("Missing listening port.");
    BoneMesh boneMesh = new BoneMesh(
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
          Node node = boneMesh.nodeMap.getNodeByLabel(target);
          if(node != null) {
            boneMesh.sendDatum(node.getLabel(), new JSONObject()
                .put("line", line.substring(line.indexOf(' ') + 1)));
            continue;
          }
        }
      } catch(Exception e) { }
      boneMesh.broadcastDatum(new JSONObject().put("line", line));
    }
    scanner.close();
    boneMesh.kill();
    boneMesh.logger.logInfo("BONEMESH", "Goodbye! :)");
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
    HelloMessage message = new HelloMessage(instanceLabel, label);
    Payload payload = new Payload(message, node.getIP(), node.getPort(), this);
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
    boolean success = true;
    for(Node node : nodeMap.getNodes())
      success = sendDatum(node.getLabel(), datum) && success;
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
    Node node = nodeMap.getNodeByLabel(target);
    if(node == null) return false;
    GenericMessage message = new GenericMessage(instanceLabel, node.getLabel(), datum);
    Payload payload = new Payload(message, node.getIP(), node.getPort(), this);
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
   * Retrieves all known nodes.
   * 
   * @return a set of all known nodes
   */
  public Set<Node> getNodes() {
    return nodeMap.getNodes();
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
          Thread.sleep(10000L);
          for(Node node : nodeMap.getNodes()) {
            HelloMessage message = new HelloMessage(instanceLabel, node.getLabel());
            Payload payload = new Payload(message, node.getIP(), node.getPort(), BoneMesh.this, false);
            socketClient.queuePayload(payload);
          }
        }
      } catch(InterruptedException e) { }
    }
  }
  
}
