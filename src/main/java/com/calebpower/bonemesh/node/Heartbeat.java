package com.calebpower.bonemesh.node;

import com.calebpower.bonemesh.BoneMesh;
import com.calebpower.bonemesh.tx.PingTx;

public class Heartbeat implements Runnable {
  
  private BoneMesh boneMesh = null;
  private Thread thread = null;
  
  @Override public void run() {
    try {
      for(;;) {
        Thread.sleep(1000L);
        for(Node node : boneMesh.getNodeList()) {
          if(node.getIncomingDataHandler() != null && node.isStale())
            if(node.getIncomingDataHandler().send(
                new PingTx(
                    boneMesh.getUUID(),
                    node.getUUID(),
                    node.getInformalName()))) {
              node.touch();
            } else {
              System.out.println("Heartbeat failed!");
            }
        }
      }
    } catch(InterruptedException e) { }
  }
  
  public static Heartbeat defibrillate(BoneMesh boneMesh) {
    Heartbeat heartbeat = new Heartbeat();
    heartbeat.boneMesh = boneMesh;
    heartbeat.thread = new Thread(heartbeat);
    heartbeat.thread.setDaemon(true);
    heartbeat.thread.start();
    return heartbeat;
  }
  
}
