package com.calebpower.bonemesh.message;

import com.calebpower.bonemesh.server.ServerNode;

public class DeathNote extends Message {
  
  public DeathNote(ServerNode sendingNode) {
    super(sendingNode.getName(), Action.DEATH, null);
  }
  
}
