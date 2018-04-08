package com.calebpower.bonemesh.listener;

import org.json.JSONObject;

public interface JSONListener {
  
  public JSONObject reactToJSON(JSONObject message);
  
}
