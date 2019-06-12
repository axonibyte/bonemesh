package com.calebpower.bonemesh.defunct.message;

import org.json.JSONObject;

import com.calebpower.bonemesh.defunct.server.ServerNode;

/**
 * A server welfare check.
 * TODO in the future replace realtime checks with on-demand checks
 * 
 * @author Caleb Power
 */
public class WelfareCheck extends Message {
  
  public WelfareCheck(ServerNode sendingNode) {
    super(sendingNode.getName(), Action.WELFARE, new JSONObject()
        .put("externalHost", sendingNode.getExternalHost())
        .put("internalHost", sendingNode.getInternalHost())
        .put("port", sendingNode.getPort()));
  }
  
}
