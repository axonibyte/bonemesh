package com.calebpower.bonemesh.message;

import org.json.JSONObject;

import com.calebpower.bonemesh.server.ServerNode;

public class AckMessage extends Message {

  public AckMessage(ServerNode sendingNode, boolean ok) {
    super(sendingNode.getName(), Action.ACK, new JSONObject()
        .put("status", ok ? "ok" : "fail"));
  }

}
