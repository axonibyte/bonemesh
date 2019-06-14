package com.calebpower.bonemesh.listener.cheap;

import org.json.JSONObject;

import com.calebpower.bonemesh.Logger;
import com.calebpower.bonemesh.listener.DataListener;

/**
 * Quick implementation of the data listener.
 * 
 * @author Caleb L. power
 */
public class CheapDataListener implements DataListener {
  
  private Logger logger = null;
  
  /**
   * Overloaded constructor.
   * 
   * @param logger the logger
   */
  public CheapDataListener(Logger logger) {
    this.logger = logger;
  }
  
  /**
   * {@inheritDoc}
   */
  @Override public void digest(JSONObject message) {
    logger.logDebug("CHEAP_DATA_LISTENER", String.format("Caught message '%1$s'", message));
  }

}
