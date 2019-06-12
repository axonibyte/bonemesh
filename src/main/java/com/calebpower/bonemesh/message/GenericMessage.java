package com.calebpower.bonemesh.message;

import org.json.JSONException;
import org.json.JSONObject;

public class GenericMessage extends JSONObject {
  
  public GenericMessage(String from, String to, JSONObject payload) {
    this(from, to, "generic", payload);
  }
  
  protected GenericMessage(String from, String to, String action, JSONObject payload) {
    put("from", from);
    put("to", to);
    put("action", action);
    put("payload", payload == null ? new JSONObject() : payload);
  }
  
  public static boolean isImplementedBy(JSONObject data) {
    try {
      return data.getString("action").equals("generic");
    } catch(JSONException e) { }
    return false;
  }
  
}
