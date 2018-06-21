package com.calebpower.bonemesh.server;

import java.util.HashMap;
import java.util.Map;

import com.calebpower.bonemesh.BoneMesh;
import com.calebpower.bonemesh.message.DeathNote;
import com.calebpower.bonemesh.message.InitRequest;
import com.calebpower.bonemesh.message.WelfareCheck;

public class NodeWatcher implements Runnable {
  
  private static final int MAX_RETRIES = 3;
  
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
      Map<String, Integer> deadList = new HashMap<>();
      
      do {
        nodeList = boneMesh.getNodeList();
        
        for(String serverNode : nodeList.keySet()) {
          if(!nodeList.get(serverNode)) {
            
            if(deadList.containsKey(serverNode)) {
              if(deadList.get(serverNode) > MAX_RETRIES) {
                boneMesh.log("Maximum number of retries for server " + serverNode + " has been reached.");
                boneMesh.unload(serverNode);
                deadList.remove(serverNode);
                continue;
              }
              deadList.replace(serverNode, deadList.get(serverNode) + 1);
            } else deadList.put(serverNode, 1);
            
            boneMesh.log("Refreshing node " + serverNode + " (try #" + deadList.get(serverNode) + ")...");
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
