package com.calebpower.bonemesh.defunct.listener;

import org.json.JSONObject;

/**
 * A BoneMeshOld data listener.
 * 
 * @author Caleb L. Power
 */
public interface BoneMeshDataListener {
  
  /**
   * React to a BoneMeshOld JSON message sent over the network.
   * 
   * @param message the message to react to
   */
  public void digest(JSONObject message);
  
  /**
   * Determines whether or not this listener should eavesdrop on messages to
   * other plugins in addition to its own.
   * 
   * @return <code>true</code> if the listener should eavesdrop on all messages or
   *         <code>false</code> if the listener should mind its own business
   */
  public boolean eavesdrop();
  
  /**
   * Retrieves the listener's identifier.
   * 
   * @return String representation of the listener's ID or
   *         <code>null</code> if the listener has no ID
   */
  public String getID();
  
}
