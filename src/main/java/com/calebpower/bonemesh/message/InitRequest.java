package com.calebpower.bonemesh.message;

import org.json.JSONObject;

import com.calebpower.bonemesh.server.ServerNode;

public class InitRequest extends Message {
  
  public InitRequest(ServerNode sendingNode) {
    super(sendingNode.getName(), Action.INIT, new JSONObject()
        .put("externalHost", sendingNode.getExternalHost())
        .put("internalHost", sendingNode.getInternalHost())
        .put("port", sendingNode.getPort()));
  }
  
}
