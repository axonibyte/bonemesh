/*
 * Copyright (c) 2019 Axonibyte Innovations, LLC. All rights reserved.
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
 * A generic message to be sent in a payload.
 * 
 * @author Caleb L. power
 */
public class GenericMessage extends JSONObject {
  
  /**
   * Overloaded constructor.
   * 
   * @param from the node from which the message is sent
   * @param to the recipient node
   * @param payload the payload
   */
  public GenericMessage(String from, String to, JSONObject payload) {
    this(from, to, "generic", payload);
  }
  
  /**
   * Overloaded constructor that provides custom action metadata.
   * 
   * @param from the node from which the message is sent
   * @param to the recipient node
   * @param action the custom action denoted in this message
   * @param payload the payload that is to be sent
   */
  protected GenericMessage(String from, String to, String action, JSONObject payload) {
    put("from", from);
    put("to", to);
    put("action", action);
    put("payload", payload == null ? new JSONObject() : payload);
  }
  
  /**
   * Determines if an incoming JSON object implements a generic message
   * with no custom action.
   * 
   * @param data the incoming data
   * @return <code>true</code> if the action is of type <code>generic</code>
   */
  public static boolean isImplementedBy(JSONObject data) {
    try {
      return data.getString("action").equals("generic");
    } catch(JSONException e) { }
    return false;
  }
  
}
