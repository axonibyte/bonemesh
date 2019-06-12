package com.calebpower.bonemesh.message;

import org.json.JSONException;
import org.json.JSONObject;

public class AckMessage extends GenericMessage {
  
  public AckMessage(String from, String to) {
    super(from, to, "ack", null);
  }
  
  public AckMessage(JSONObject json) throws JSONException {
    // intentionally flip values
    this(json.getString("to"), json.getString("from"));
  }
  
  public static boolean isImplementedBy(JSONObject data) {
    try {
      return data.getString("action").equals("ack");
    } catch(JSONException e) { }
    return false;
  }
  
}
