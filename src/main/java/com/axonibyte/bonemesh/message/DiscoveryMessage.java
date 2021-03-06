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
import java.util.concurrent.ConcurrentHashMap;

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
   * @param knownNodes directly connected nodes and their latencies
   * @param port the BoneMesh listening port
   */
  public DiscoveryMessage(String from, String to, Map<String, Long> knownNodes, int port) {
    super(from, to, "hello", null);
    JSONArray nodes = new JSONArray();
    for(String node : knownNodes.keySet())
      nodes.put(new JSONObject()
          .put("node", node)
          .put("latency", knownNodes.get(node)));
    getJSONObject("payload")
        .put("nodes", nodes)
        .put("port", port);
  }
  
  /**
   * Generates a discovery message from a JSON object.
   * 
   * @param json the raw JSON object
   * @throws JSONException if there is unexpected data or lack thereof
   */
  public DiscoveryMessage(JSONObject json) throws JSONException {
    super(json);
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
  
  /**
   * Retrieves a map of neighbors and their latencies.
   * 
   * @return map of node neighbors and their latencies
   */
  public Map<String, Long> getNodes() {
    Map<String, Long> latencies = new ConcurrentHashMap<>();
    JSONArray nodes = getJSONObject("payload").getJSONArray("nodes");
    for(int i = 0; i < nodes.length(); i++) {
      latencies.put(nodes.getJSONObject(i).getString("node"),
          nodes.getJSONObject(i).getLong("latency"));
    }
    return latencies;
  }
  
  /**
   * Retrieves the listening port for the sender.
   * 
   * @return integer denoting the listening port
   */
  public int getPort() {
    return getJSONObject("payload").getInt("port");
  }
}
