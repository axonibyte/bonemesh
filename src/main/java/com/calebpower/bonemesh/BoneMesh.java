package com.calebpower.bonemesh;

import java.util.Scanner;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.json.JSONException;
import org.json.JSONObject;

import com.calebpower.bonemesh.listener.AckListener;
import com.calebpower.bonemesh.listener.CheapDataListenerImpl;
import com.calebpower.bonemesh.listener.DataListener;
import com.calebpower.bonemesh.message.GenericMessage;
import com.calebpower.bonemesh.message.HelloMessage;
import com.calebpower.bonemesh.node.Node;
import com.calebpower.bonemesh.node.NodeMap;
import com.calebpower.bonemesh.socket.Payload;
import com.calebpower.bonemesh.socket.SocketClient;
import com.calebpower.bonemesh.socket.SocketServer;

public class BoneMesh implements AckListener {
  
  private NodeMap nodeMap = null;
  private SocketClient socketClient = null;
  private SocketServer socketServer = null;
  private String instanceLabel = null;
  
  public BoneMesh(String label, int port) {
    this.instanceLabel = label;
    this.nodeMap = new NodeMap();
    this.socketClient = SocketClient.build();
    this.socketServer = SocketServer.build(port);
  }
  
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
    if(cmd.hasOption("target_nodes")) {
      String[] targetNodes = cmd.getOptionValues("target_nodes");
      for(String targetNode : targetNodes) {
        String[] nodeArgs = targetNode.split("=");
        boneMesh.addNode(nodeArgs[0], nodeArgs[1]);
      }
    }
    
    System.out.println("PROMPT IS READY");
    
    DataListener listener = new CheapDataListenerImpl();
    boneMesh.addDataListener(listener);
    Scanner scanner = new Scanner(System.in);
    String line = null;
    while((line = scanner.nextLine()) != null && line.length() != 0) {
      for(Node node : boneMesh.nodeMap.getNodes()) {
        boneMesh.sendDatum(node.getLabel(), new JSONObject().put("line", line));
      }
    }
    scanner.close();
    boneMesh.kill();
    System.out.println("goodbye!");
  }
  
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
  
  public void removeNode(String label) {
    Node node = nodeMap.getNodeByLabel(label);
    if(node != null) nodeMap.removeNode(node);
  }
  
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
      if(node != null)
        nodeMap.setNodeAlive(node, alive);
      System.out.printf("Attempted to set node %1$s to alive=%2$b\n", target, alive);
    } catch(JSONException e) {
      e.printStackTrace();
    }
  }
  
  public void addDataListener(DataListener listener) {
    socketServer.addDataListener(listener);
  }
  
  public void removeDataListener(DataListener listener) {
    socketServer.removeDataListener(listener);
  }
  
  public void kill() {
    socketClient.kill();
    socketServer.kill();
  }

  @Override public void receiveAck(Payload payload) {
    setNodeStatus(payload, true);
  }

  @Override public void receiveNak(Payload payload) {
    setNodeStatus(payload, false);
  }
  
}
