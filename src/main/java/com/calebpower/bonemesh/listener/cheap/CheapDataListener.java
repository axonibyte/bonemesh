package com.calebpower.bonemesh.listener.cheap;

import org.json.JSONObject;

import com.calebpower.bonemesh.Logger;
import com.calebpower.bonemesh.listener.DataListener;

public class CheapDataListener implements DataListener {
  
  private Logger logger = null;
  
  public CheapDataListener(Logger logger) {
    this.logger = logger;
  }
  
  @Override public void digest(JSONObject message) {
    logger.logDebug("CHEAP_DATA_LISTENER", String.format("Caught message '%1$s'", message));
  }

}
