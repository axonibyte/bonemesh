package com.calebpower.bonemesh.listener;

import org.json.JSONObject;

public interface BoneMeshDataListener {
  
  public JSONObject reactToJSON(JSONObject message);
  
}
