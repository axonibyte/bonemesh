package com.calebpower.bonemesh.defunct.message;

import org.json.JSONObject;

import com.calebpower.bonemesh.defunct.server.ServerNode;

/**
 * A request that notifies a server of the existence of a new node.
 * 
 * @author Caleb L. Power
 */
public class InitRequest extends Message {
  
  /**
   * Overloaded constructor for the initialization request.
   * 
   * @param sendingNode the node of origination
   */
  public InitRequest(ServerNode sendingNode) {
    super(sendingNode.getName(), Action.INIT, new JSONObject()
        .put("externalHost", sendingNode.getExternalHost())
        .put("internalHost", sendingNode.getInternalHost())
        .put("port", sendingNode.getPort()));
  }
  
}
