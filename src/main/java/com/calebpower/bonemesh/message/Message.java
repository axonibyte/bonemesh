package com.calebpower.bonemesh.message;

import org.json.JSONObject;

public class Message extends JSONObject {
  
  public static enum Action {
    ACK,
    INIT,
    DEATH,
    DISCOVER,
    TRANSMIT,
    WELFARE;
  }
  
  protected Message(String sendingNode, Action action, JSONObject payload) {  
    put("bonemesh", new JSONObject()
        .put("action", action.toString())
        .put("from", sendingNode));
    if(payload != null) put("payload", payload);
  }
  
  protected Message setPayload(JSONObject payload) {
    if(has("payload")) remove("payload");
    put("payload", payload);
    return this;
  }
  
}
