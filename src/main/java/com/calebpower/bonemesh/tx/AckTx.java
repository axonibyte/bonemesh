package com.calebpower.bonemesh.tx;

import java.util.UUID;

import org.json.JSONObject;

import com.calebpower.bonemesh.BoneMesh;
import com.calebpower.bonemesh.exception.BadTxException;
import com.calebpower.bonemesh.socket.IncomingDataHandler;

public class AckTx extends GenericTx {
  
  public AckTx(UUID thisNode, UUID targetNode) {
    super(thisNode, targetNode, TxType.ACK_TX,
        new JSONObject()
          .put("status", "ok"));
  }
  
  public AckTx(JSONObject json) throws BadTxException {
    super(json);
    validateMessageType(TxType.ACK_TX);
    if(json.has("status"))
      throw new BadTxException("Malformed ACK transaction.");
  }
  
  @Override public void followUp(BoneMesh boneMesh, IncomingDataHandler incomingDataHandler) {
    linkNode(boneMesh, incomingDataHandler);
    // TODO execute ack transaction
  }
  
}
