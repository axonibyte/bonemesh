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

import java.util.Map;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * A heartbeat message intended to check if a node is alive.
 * 
 * @author Caleb L. Power
 */
public class DiscoveryMessage extends GenericMessage {
  
  /**
   * Overloaded constructor.
   * 
   * @param from the node from which the message is sent
   * @param to the recipient node
   * @param latencies known and living nodes and their latencies
   */
  public DiscoveryMessage(String from, String to, Map<String, Long> latencies) {
    super(from, to, "hello", null);
    JSONArray nodes = new JSONArray();
    for(String node : latencies.keySet())
      nodes.put(new JSONObject()
          .put("node", node)
          .put("latency", latencies.get(node)));
    getJSONObject("payload").put("nodes", nodes);
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
