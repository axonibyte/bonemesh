/*
 * Copyright (c) 2019-2023 Axonibyte Innovations, LLC. All rights reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.axonibyte.bonemesh.message;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * A heartbeat message intended to respond to incoming messages.
 * 
 * @author Caleb L. Power <cpower@axonibyte.com>
 */
public class AckMessage extends GenericMessage {
  
  /**
   * Instantiates an ACK message.
   * 
   * @param from the node from which the message is sent
   * @param to the recipient node
   */
  public AckMessage(String from, String to) {
    super(from, to, "ack", null);
  }

  /**
   * Instantiates an ACK message with a pubkey attached.
   *
   * @param from the node from which the message is sent
   * @param to the recipient node
   * @param pubkey the pubkey associated with the sender
   */
  public AckMessage(String from, String to, String pubkey) {
    super(from, to, "ack", new JSONObject("pubkey", pubkey));
  }
  
  /**
   * Generates an ACK message from incoming data.
   * Intentionally flips the "to" and "from" values.
   * 
   * @param json the incoming data
   * @param flip <code>true</code> to receive the ACK,
   *        or <code>false</code> to pass it on
   * @throws JSONException to be thrown if the JSON object couldn't be parsed
   */
  public AckMessage(JSONObject json, boolean flip) throws JSONException {
    this(json.getString(flip ? "to" : "from"),
        json.getString(flip ? "from" : "to"));
    // if(json.has("payload")) put("payload", json.getJSONObject("payload"));
  }

  /**
   * Determines whether or not the ACK has a pubkey attached.
   *
   * @return {@code true} iff a pubkey is attached
   */
  public boolean hasPubkey() {
    return getJSONObject("payload").has("pubkey");
  }

  /**
   * Retrieves the pubkey attached to the ACK if one exists.
   *
   * @return the Base64-encoded String representation of the pubkey
   */
  public String getPubkey() {
    return getJSONObject("payload").getString("pubkey");
  }

  /**
   * Sets the pubkey attached to the ACK.
   *
   * @param pubkey the Base64-encoded String representation of the pubkey
   */
  public void setPubkey(String pubkey) {
    getJSONObject("payload").put("pubkey", pubkey);
  }
  
  /**
   * Determines if an incoming JSON object implements a ack-type message.
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
