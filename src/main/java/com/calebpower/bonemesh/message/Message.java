package com.calebpower.bonemesh.message;

import org.json.JSONObject;

/**
 * A generic message to be sent to a target node.
 * 
 * @author Caleb L. Power
 */
public class Message extends JSONObject {
  
  /**
   * A particular action associated with the message.
   * 
   * @author Caleb L. Power
   */
  public static enum Action {
    /**
     * Acknowledgement message.
     */
    ACK,
    
    /**
     * Initialization request.
     */
    INIT,
    
    /**
     * Death note.
     */
    DEATH,
    
    /**
     * Discovery message.
     */
    DISCOVER,
    
    /**
     * Transmission request.
     */
    TRANSMIT,
    
    /**
     * Welfare check.
     */
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
