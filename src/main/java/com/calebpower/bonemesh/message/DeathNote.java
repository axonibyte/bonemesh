package com.calebpower.bonemesh.message;

import com.calebpower.bonemesh.server.ServerNode;

/**
 * Message to be sent when a server leaves the network. Generally, this will be
 * sent to all known nodes at the same time.
 * 
 * @author Caleb L. Power
 */
public class DeathNote extends Message {
  
  /**
   * Overloaded constructor for the death note.
   * 
   * @param sendingNode the node of origination
   */
  public DeathNote(ServerNode sendingNode) {
    super(sendingNode.getName(), Action.DEATH, null);
  }
  
}
