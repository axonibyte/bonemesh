package com.calebpower.bonemesh.listener;

import org.json.JSONObject;

public class CheapDataListenerImpl implements DataListener {

  @Override public void digest(JSONObject message) {
    System.out.println("DATA LISTENER CAUGHT: " + message);
  }

}
