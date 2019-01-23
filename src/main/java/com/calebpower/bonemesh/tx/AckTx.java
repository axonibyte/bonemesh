package com.calebpower.bonemesh.tx;

import java.util.UUID;

import org.json.JSONObject;

import com.calebpower.bonemesh.BoneMesh;
import com.calebpower.bonemesh.exception.BadTxException;

public class AckTx extends GenericTx {
  
  private static String MESSAGE_TYPE = "ack";
  
  public AckTx(UUID thisNode, UUID targetNode) {
    super(thisNode, targetNode, TxType.ACK_TX,
        new JSONObject()
          .put("status", "ok"));
  }
  
  public AckTx(JSONObject json) throws BadTxException {
    super(json);
    validateMessageType(TxType.ACK_TX);
  }
  
  @Override public void execute(BoneMesh boneMesh) {
    // TODO execute ack transaction
  }
  
}
