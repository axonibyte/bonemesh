package com.calebpower.bonemesh.listener;

import org.json.JSONObject;

/**
 * A BoneMesh incoming data listener.
 * 
 * @author Caleb L. Power
 */
public interface DataListener {
  
  /**
   * Digests good non-ACK data coming from another node.
   * 
   * @param message the JSON object containing the message
   */
  public void digest(JSONObject message);
  
}
