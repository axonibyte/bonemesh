package com.calebpower.bonemesh.message;

import org.json.JSONObject;

import com.calebpower.bonemesh.server.ServerNode;

/**
 * An acknowledgement message for responses.
 * 
 * @author Caleb L. Power
 */
public class AckMessage extends Message {

  /**
   * Overloaded constructor for the acknowledgement message.
   * 
   * @param sendingNode the node of origination
   * @param ok <code>true</code> on a successful transaction or
   *           <code>false</code> on a failed transaction
   */
  public AckMessage(ServerNode sendingNode, boolean ok) {
    super(sendingNode.getName(), Action.ACK, new JSONObject()
        .put("status", ok ? "ok" : "fail"));
  }

}
