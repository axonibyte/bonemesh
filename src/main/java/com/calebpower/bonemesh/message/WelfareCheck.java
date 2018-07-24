package com.calebpower.bonemesh.message;

import org.json.JSONObject;

import com.calebpower.bonemesh.server.ServerNode;

public class WelfareCheck extends Message {
  
  public WelfareCheck(ServerNode sendingNode) {
    super(sendingNode.getName(), Action.WELFARE, new JSONObject()
        .put("externalHost", sendingNode.getExternalHost())
        .put("internalHost", sendingNode.getInternalHost())
        .put("port", sendingNode.getPort()));
  }
  
}
