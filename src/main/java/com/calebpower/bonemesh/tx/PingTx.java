package com.calebpower.bonemesh.tx;

import java.util.UUID;

import org.json.JSONObject;

import com.calebpower.bonemesh.BoneMesh;
import com.calebpower.bonemesh.exception.BadTxException;
import com.calebpower.bonemesh.socket.IncomingDataHandler;

public class PingTx extends GenericTx {
  
  public PingTx(UUID thisNode, UUID targetNode, String thisInformalID) {
    super(thisNode, targetNode, TxType.PING_TX);
  }
  
  public PingTx(JSONObject json) throws BadTxException {
    super(json);
    validateMessageType(TxType.PING_TX);
  }
  
  @Override public void followUp(BoneMesh boneMesh, IncomingDataHandler incomingDataHandler) {
    linkNode(boneMesh, incomingDataHandler);
    // TODO execute ping transaction
  }
  
}
