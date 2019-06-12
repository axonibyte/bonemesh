package com.calebpower.bonemesh.message;

import org.json.JSONException;
import org.json.JSONObject;

public class HelloMessage extends GenericMessage {
  
  public HelloMessage(String from, String to) {
    super(from, to, "hello", null);
  }
  
  public static boolean isImplementedBy(JSONObject data) {
    try {
      return data.getString("action").equals("hello");
    } catch(JSONException e) { }
    return false;
  }
  
}
