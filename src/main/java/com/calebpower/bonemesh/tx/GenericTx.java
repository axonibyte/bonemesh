package com.calebpower.bonemesh.tx;

import java.util.UUID;

import org.json.JSONException;
import org.json.JSONObject;

import com.calebpower.bonemesh.BoneMesh;
import com.calebpower.bonemesh.exception.BadTxException;

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
        .put("targetNode", targetNode.toString())
        .put("messageID", messageID.toString())
        .put("messageType", messageType == null ? TxType.GENERIC_TX : messageType));
    if(data != null) put("data", data);
  }
  
  public GenericTx(JSONObject json) throws BadTxException {
    try {
      JSONObject meta = json.getJSONObject("meta");
      JSONObject data = json.getJSONObject("data");
      put("meta", new JSONObject()
          .put("originNode", meta.getString("originNode"))
          .put("targetNode", meta.getString("targetNode"))
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
      if(!getJSONObject("meta").getString("messageType").equalsIgnoreCase(messageType.toString()))
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
  
  public void execute(BoneMesh boneMesh) {
    // TODO execute generic transaction
  }
  
}
