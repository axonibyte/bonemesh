package com.calebpower.bonemesh.tx;

import java.util.UUID;

import org.json.JSONObject;

import com.calebpower.bonemesh.exception.BadTxException;

public class AckTx extends GenericTx {
  
  private static String MESSAGE_TYPE = "ack";
  
  public AckTx(UUID thisNode, UUID targetNode) {
    super(thisNode, targetNode, MESSAGE_TYPE,
        new JSONObject()
          .put("status", "ok"));
  }
  
  public AckTx(JSONObject json) throws BadTxException {
    super(json);
    validateMessageType(MESSAGE_TYPE);
  }
  
}
