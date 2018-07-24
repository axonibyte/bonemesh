package com.calebpower.bonemesh.listener;

import org.json.JSONObject;

/**
 * A BoneMesh data listener.
 * 
 * @author Caleb L. Power
 */
public interface BoneMeshDataListener {
  
  /**
   * React to a BoneMesh JSON message sent over the network.
   * 
   * @param message the message to react to
   * @return the JSON response
   */
  public JSONObject reactToJSON(JSONObject message);
  
}
