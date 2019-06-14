package com.calebpower.bonemesh.message;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * A heartbeat message intended to check if a node is alive.
 * 
 * @author Caleb L. Power
 */
public class HelloMessage extends GenericMessage {
  
  /**
   * Overloaded constructor.
   * 
   * @param from the node from which the message is sent
   * @param to the recipient node
   */
  public HelloMessage(String from, String to) {
    super(from, to, "hello", null);
  }
  
  /**
   * Determines if an incoming JSON object implements a hello-type message.
   * 
   * @param data the incoming data
   * @return <code>true</code> if the action is of type <code>hello</code>
   */
  public static boolean isImplementedBy(JSONObject data) {
    try {
      return data.getString("action").equals("hello");
    } catch(JSONException e) { }
    return false;
  }
  
}
