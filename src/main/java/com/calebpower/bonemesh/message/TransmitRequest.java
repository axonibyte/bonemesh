package com.calebpower.bonemesh.message;

import org.json.JSONObject;

import com.calebpower.bonemesh.server.ServerNode;

public class TransmitRequest extends Message{
  
  public TransmitRequest(ServerNode sendingNode, JSONObject payload) {
    super(sendingNode.getName(), Action.TRANSMIT, payload);
  }
  
}
