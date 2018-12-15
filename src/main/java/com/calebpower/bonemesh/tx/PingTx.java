package com.calebpower.bonemesh.tx;

import java.util.UUID;

import org.json.JSONObject;

import com.calebpower.bonemesh.exception.BadTxException;

public class PingTx extends GenericTx {
  
  private static String MESSAGE_TYPE = "ping";
  
  public PingTx(UUID thisNode, UUID targetNode, String thisInformalID) {
    super(thisNode, targetNode, MESSAGE_TYPE);
  }
  
  public PingTx(JSONObject json) throws BadTxException {
    super(json);
    validateMessageType(MESSAGE_TYPE);
  }
  
}
