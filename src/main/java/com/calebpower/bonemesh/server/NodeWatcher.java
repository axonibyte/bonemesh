package com.calebpower.bonemesh.server;

import java.util.Map;

import com.calebpower.bonemesh.BoneMesh;
import com.calebpower.bonemesh.message.WelfareCheck;
import com.calebpower.bonemesh.message.DeathNote;
import com.calebpower.bonemesh.message.InitRequest;

public class NodeWatcher implements Runnable {
  
  private BoneMesh boneMesh = null;
  
  public NodeWatcher(BoneMesh boneMesh) {
    this.boneMesh = boneMesh;
  }
  
  @Override public void run() {
    for(;;) {
      try {
        Thread.sleep(10000L);
      } catch(InterruptedException e) { }
      
      boneMesh.log("Dispatching ack message...");
      boneMesh.dispatch(new WelfareCheck(boneMesh.getThisServer()));

      try {
        Thread.sleep(5000L);
      } catch(InterruptedException e) { }
      
      Map<String, Boolean> nodeList = null;
      
      do {
        nodeList = boneMesh.getNodeList();
        
        for(String serverNode : nodeList.keySet()) {
          if(!nodeList.get(serverNode)) {
            boneMesh.log("Refreshing node " + serverNode + "...");
            boneMesh.dispatch(new DeathNote(boneMesh.getThisServer()), serverNode);
            
            try {
              Thread.sleep(2000L);
            } catch(InterruptedException e) { }
            
            boneMesh.log("Bringing node " + serverNode + " back online...");
            boneMesh.dispatch(new InitRequest(boneMesh.getThisServer()), serverNode);
          }
        }
        
        try {
          Thread.sleep(5000L);
        } catch(InterruptedException e) { }
      } while(nodeList.containsValue(false));
    }
  }
  
  
  
}
