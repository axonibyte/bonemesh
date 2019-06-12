package com.calebpower.bonemesh.listener;

import com.calebpower.bonemesh.socket.Payload;

public interface AckListener {
  
  public void receiveAck(Payload payload);
  
  public void receiveNak(Payload payload);
  
}
