package com.calebpower.bonemesh.tx;

import java.util.UUID;

import org.json.JSONException;
import org.json.JSONObject;

import com.calebpower.bonemesh.exception.BadTxException;

public class GenericTx extends JSONObject {
  
  public GenericTx(UUID thisNode, UUID targetNode, String messageType) {
    this(thisNode, targetNode, messageType, new JSONObject());
  }
  
  public GenericTx(UUID thisNode, UUID targetNode, String messageType, JSONObject data) {
    this(thisNode, targetNode, UUID.randomUUID(), messageType, data); // generate a random UUID for this message
  }
  
  public GenericTx(UUID originNode, UUID targetNode, UUID messageID, String messageType, JSONObject data) {
    put("meta", new JSONObject()
        .put("originNode", originNode.toString())
        .put("targetNode", targetNode.toString())
        .put("messageID", messageID.toString())
        .put("messageType", messageType == null ? "generic" : messageType));
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
  
  protected void validateMessageType(String messageType) throws BadTxException {
    try {
      if(!getJSONObject("meta").getString("messageType").equalsIgnoreCase(messageType))
        throw new BadTxException("The processed message was not of type " + messageType);
    } catch(JSONException e) {
      throw new BadTxException(this, e.getMessage());
    }
  }
  
}
