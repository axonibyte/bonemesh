package com.calebpower.bonemesh;

import org.json.JSONException;
import org.json.JSONObject;

import com.calebpower.bonemesh.listener.AckListener;
import com.calebpower.bonemesh.message.GenericMessage;
import com.calebpower.bonemesh.node.Node;
import com.calebpower.bonemesh.node.NodeMap;
import com.calebpower.bonemesh.socket.Payload;
import com.calebpower.bonemesh.socket.SocketClient;

public class BoneMesh implements AckListener {
  
  private NodeMap nodeMap = null;
  private SocketClient socketClient = null;
  private String instanceLabel = null;
  
  public BoneMesh(String label) {
    this.instanceLabel = label;
    this.nodeMap = new NodeMap();
    this.socketClient = SocketClient.build();
  }
  
  public static void main(String[] args) {
    System.out.println("Hello, world!");
  }
  
  public void addNode(String label, String address) throws Exception { // this is a synchronous (blocking) method
    if(label == null) throw new Exception("Node label cannot be null.");
    if(address == null) throw new Exception("Node address cannot be null.");
    String[] splitAddress = address.split(":");
    if(splitAddress.length != 2) throw new Exception("Invalid node address.");
    int port = Integer.parseInt(splitAddress[1]);
    Node node = new Node(label, splitAddress[0], port);
    nodeMap.addOrReplaceNode(node, false);
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
      System.out.printf("Attempted to set node %1$s to alive=%2$b", target, alive);
    } catch(JSONException e) {
      e.printStackTrace();
    }
  }

  @Override public void receiveAck(Payload payload) {
    setNodeStatus(payload, true);
  }

  @Override public void receiveNak(Payload payload) {
    setNodeStatus(payload, false);
  }
  
}
