package com.calebpower.bonemesh.listener;

import com.calebpower.bonemesh.socket.Payload;

/**
 * Listens for ACKs or NAKs.
 * 
 * @author Caleb L. Power
 */
public interface AckListener {
  
  /**
   * Receives an ACK message with the originally-sent payload.
   * 
   * @param payload the payload
   */
  public void receiveAck(Payload payload);
  
  /**
   * Receives a NAK message with the originally-sent payload.
   * 
   * @param payload the payload
   */
  public void receiveNak(Payload payload);
  
}
