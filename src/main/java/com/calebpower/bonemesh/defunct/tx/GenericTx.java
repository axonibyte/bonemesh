package com.calebpower.bonemesh.defunct.tx;

import java.util.UUID;

import org.json.JSONException;
import org.json.JSONObject;

import com.calebpower.bonemesh.defunct.BoneMesh;
import com.calebpower.bonemesh.defunct.exception.BadTxException;
import com.calebpower.bonemesh.defunct.node.Node;
import com.calebpower.bonemesh.defunct.socket.IncomingDataHandler;

public class GenericTx extends JSONObject {
  
  public static enum TxType {
    GENERIC_TX("generic"),
    ACK_TX("ack"),
    MAP_TX("map"),
    PING_TX("ping");
    
    private String tag = null;
    
    private TxType(String tag) {
      this.tag = tag;
    }
    
    @Override public String toString() {
      return tag;
    }
    
    public static TxType fromString(String tag) {
      for(TxType txType : values())
        if(tag.equalsIgnoreCase(txType.tag)) return txType;
      return null;
    }
  }
  
  public GenericTx(UUID thisNode, UUID targetNode, TxType messageType) {
    this(thisNode, targetNode, messageType, new JSONObject());
  }
  
  public GenericTx(UUID thisNode, UUID targetNode, TxType messageType, JSONObject data) {
    this(thisNode, targetNode, UUID.randomUUID(), messageType, data); // generate a random UUID for this message
  }
  
  public GenericTx(UUID originNode, UUID targetNode, UUID messageID, TxType messageType, JSONObject data) {
    put("meta", new JSONObject()
        .put("originNode", originNode.toString())
        .put("targetNode", targetNode == null ? JSONObject.NULL : targetNode.toString())
        .put("messageID", messageID.toString())
        .put("messageType", messageType == null ? TxType.GENERIC_TX.toString() : messageType.toString()));
    if(data != null) put("data", data);
  }
  
  public GenericTx(UUID originNode, UUID targetNode, JSONObject data) {
    this(originNode, targetNode, TxType.GENERIC_TX, data);
  }
  
  public GenericTx(JSONObject json) throws BadTxException {
    try {
      JSONObject meta = json.getJSONObject("meta");
      JSONObject data = json.getJSONObject("data");
      put("meta", new JSONObject()
          .put("originNode", meta.getString("originNode"))
          .put("targetNode", meta.isNull("targetNode") ? JSONObject.NULL : meta.getString("targetNode"))
          .put("messageID", meta.getString("messageID"))
          .put("messageType", meta.getString("messageType")));
      put("data", data);
    } catch(JSONException e) {
      throw new BadTxException(json, e.getMessage());
    }
  }
  
  public GenericTx setData(JSONObject data) {
    if(has("data")) remove("data");
    put("data", data);
    return this;
  }
  
  protected void validateMessageType(TxType messageType) throws BadTxException {
    try {
      if(getMessageType() != messageType)
        throw new BadTxException("The processed message was not of type " + messageType);
    } catch(JSONException e) {
      throw new BadTxException(this, e.getMessage());
    }
  }
  
  public boolean isOfType(TxType messageType) {
    try {
      validateMessageType(messageType);
      return true;
    } catch(BadTxException e) { }
    return false;
  }
  
  protected void linkNode(BoneMesh boneMesh, IncomingDataHandler incomingDataHandler) {
    Node node = new Node()
        .setUUID(getOriginNode());
    node = boneMesh.syncNode(node);
    if(node.getIncomingDataHandler() == null)
      node.setIncomingDataHandler(incomingDataHandler);
    // TODO investigate whether data handlers need to be closed down or whatever
  }
  
  protected boolean route(BoneMesh boneMesh, IncomingDataHandler incomingDataHandler) {
    if(getTargetNode() == null) return false;
    
    UUID uuid = getTargetNode();
    
    if(uuid != null && getTargetNode().compareTo(boneMesh.getUUID()) != 0) {
      Node node = boneMesh.getBestRoute(uuid);
      if(node == null) {
        System.out.println("Node not available in map! Refunding transaction.");
        incomingDataHandler.send(this);
      } else {
        System.out.println("Found path via " + node.getInformalName());
        node.getIncomingDataHandler().send(this);
      }
      
      return true;
    }
    
    return false;
  }
  
  public void followUp(BoneMesh boneMesh, IncomingDataHandler incomingDataHandler) {
    linkNode(boneMesh, incomingDataHandler);
    boneMesh.getNodeMap().getNode(getOriginNode()).touch();
    if(getTargetNode() == null || getTargetNode().compareTo(boneMesh.getUUID()) == 0) {
      boneMesh.consumePayload(this);
    } else {
      Node node = boneMesh.getBestRoute(boneMesh.getUUID());
      if(node == null) {
        System.out.println("Node not available in map!! Refunding transaction.");
        incomingDataHandler.send(this);
      } else {
        System.out.println("Found path via " + node.getInformalName());
        node.getIncomingDataHandler().send(this);
      }
    }
  }
  
  public UUID getOriginNode() {
    try {
      return UUID.fromString(getJSONObject("meta").getString("originNode"));
    } catch(JSONException | IllegalArgumentException e) {
      e.printStackTrace();
    }
    return null;
  }
  
  public UUID getTargetNode() {
    try {
      return UUID.fromString(getJSONObject("meta").getString("targetNode"));
    } catch(JSONException | IllegalArgumentException e) { }
    return null;
  }
  
  public UUID getMessageID() {
    try {
      return UUID.fromString(getJSONObject("meta").getString("targetNode"));
    } catch(JSONException | IllegalArgumentException e) {
      e.printStackTrace();
    }
    return null;
  }
  
  public TxType getMessageType() {
    try {
      return TxType.fromString(getJSONObject("meta").getString("messageType"));
    } catch(JSONException e) {
      e.printStackTrace();
    }
    return null;
  }
  
}
