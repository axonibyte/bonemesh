package com.calebpower.bonemesh.listener;

import org.json.JSONObject;

public interface DataListener {
  
  public void digest(JSONObject message);
  
}
