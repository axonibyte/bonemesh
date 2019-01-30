package com.calebpower.bonemesh.tx;

import java.util.UUID;

import org.json.JSONObject;

import com.calebpower.bonemesh.BoneMesh;
import com.calebpower.bonemesh.exception.BadTxException;
import com.calebpower.bonemesh.node.Edge;
import com.calebpower.bonemesh.node.Node;
import com.calebpower.bonemesh.socket.IncomingDataHandler;

public class AckTx extends GenericTx {
  
  public AckTx(UUID thisNode, UUID targetNode, BoneMesh boneMesh) {
    super(thisNode, targetNode, TxType.ACK_TX,
        new JSONObject()
          .put("status", "ok"));
    //boneMesh.getNodeMap().update(new Edge(new Node().setUUID(targetNode)));
  }
  
  public AckTx(UUID thisNode, UUID targetNode, String errorMessage) {
    super(thisNode, targetNode, TxType.ACK_TX,
        new JSONObject()
          .put("status", "error")
          .put("message", errorMessage));
  }
  
  public AckTx(JSONObject json) throws BadTxException {
    super(json);
    validateMessageType(TxType.ACK_TX);
    if(json.has("status"))
      throw new BadTxException("Malformed ACK transaction.");
  }
  
  @Override public void followUp(BoneMesh boneMesh, IncomingDataHandler incomingDataHandler) {
    linkNode(boneMesh, incomingDataHandler);
    // TODO execute ack transaction (or don't, since this is an ack)
    System.out.println("\n------------------- ACK UPDATED: " + getOriginNode().toString() + " -----------------");
    try {
    System.out.println("Target node is " + getTargetNode().toString());
    } catch(Exception e) { }
    boneMesh.getNodeMap().update(new Edge(new Node().setUUID(getOriginNode())));
    route(boneMesh, incomingDataHandler);
  }
  
}
