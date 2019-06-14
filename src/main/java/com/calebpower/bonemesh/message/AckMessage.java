package com.calebpower.bonemesh.message;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * A heartbeat message intended to respond to incoming messages.
 * 
 * @author Caleb L. power
 */
public class AckMessage extends GenericMessage {
  
  /**
   * Overloaded constructor.
   * 
   * @param from the node from which the message is sent
   * @param to the recipient node
   */
  public AckMessage(String from, String to) {
    super(from, to, "ack", null);
  }
  
  /**
   * Generates an ACK message from incoming data.
   * Intentionally flips the "to" and "from" values.
   * 
   * @param json the incoming data
   * @throws JSONException to be thrown if the JSON object couldn't be parsed
   */
  public AckMessage(JSONObject json) throws JSONException {
    // intentionally flip values
    this(json.getString("to"), json.getString("from"));
  }
  
  /**
   * Determines if an incoming JSON object implements a hello-type message.
   * 
   * @param data the incoming data
   * @return <code>true</code> if the action is of type <code>ack</code>
   */
  public static boolean isImplementedBy(JSONObject data) {
    try {
      return data.getString("action").equals("ack");
    } catch(JSONException e) { }
    return false;
  }
  
}
