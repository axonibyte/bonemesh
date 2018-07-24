package com.calebpower.bonemesh.message;

import org.json.JSONObject;

import com.calebpower.bonemesh.server.ServerNode;

/**
 * Transmission request with a generic payload.
 * 
 * @author Caleb L. Power
 */
public class TransmitRequest extends Message{
  
  /**
   * Overloaded constructor for the transmission request.
   * 
   * @param sendingNode the node of origination
   * @param payload the generic payload
   */
  public TransmitRequest(ServerNode sendingNode, JSONObject payload) {
    super(sendingNode.getName(), Action.TRANSMIT, payload);
  }
  
}
