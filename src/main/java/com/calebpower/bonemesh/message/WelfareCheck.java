package com.calebpower.bonemesh.message;

import com.calebpower.bonemesh.server.ServerNode;

public class WelfareCheck extends Message {
  
  public WelfareCheck(ServerNode sendingNode) {
    super(sendingNode.getName(), Action.WELFARE, null);
  }
  
}
