/*
 * Copyright (c) 2026 Axonibyte Innovations, LLC. All rights reserved.
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

package com.axonibyte.bonemesh.v3.message;

import java.security.SecureRandom;
import java.util.HexFormat;

import org.json.JSONObject;

/**
 * Factory for the BoneMesh v3 inner message types (protocol.md &sect;4). Each
 * builder produces a JSON object that passes {@link MessageSchema}; the
 * transport layer seals it into a frame.
 *
 * @author Caleb L. Power
 */
public final class Messages {

  /** The default hop limit for application data (protocol.md §0). */
  public static final int DEFAULT_TTL = 16;

  private static final HexFormat HEX = HexFormat.of();

  private Messages() { }

  /**
   * Generates a fresh 128-bit message id as 32 lowercase-hex characters.
   *
   * @param rng the randomness source
   * @return the message id
   */
  public static String newMid(SecureRandom rng) {
    byte[] id = new byte[16];
    rng.nextBytes(id);
    return HEX.formatHex(id);
  }

  /**
   * Builds an application data message (a single, unchunked one).
   *
   * @param mid the message id
   * @param from the origin label
   * @param to the destination label
   * @param ttl the hop limit
   * @param payload the application payload
   * @return the data message
   */
  public static JSONObject data(String mid, String from, String to, int ttl, JSONObject payload) {
    return new JSONObject()
        .put("type", "data").put("mid", mid)
        .put("from", from).put("to", to).put("ttl", ttl)
        .put("payload", payload);
  }

  /**
   * Builds an acknowledgement for a message id.
   *
   * @param mid the id being acknowledged
   * @return the ack message
   */
  public static JSONObject ack(String mid) {
    return new JSONObject().put("type", "ack").put("mid", mid);
  }

  /**
   * Builds a negative acknowledgement naming the failing hop (defect D4).
   *
   * @param mid the id that could not be delivered
   * @param failedHop the label of the next hop that failed
   * @return the nak message
   */
  public static JSONObject nak(String mid, String failedHop) {
    return new JSONObject().put("type", "nak").put("mid", mid).put("hop", failedHop);
  }

  /**
   * Builds a discovery advertisement: destination labels and their path costs.
   *
   * @param costs a map of reachable label to path cost (milliseconds)
   * @return the disco message
   */
  public static JSONObject disco(java.util.Map<String, Long> costs) {
    JSONObject routes = new JSONObject();
    for(var e : costs.entrySet()) routes.put(e.getKey(), e.getValue());
    return new JSONObject().put("type", "disco").put("routes", routes);
  }

  /**
   * Builds a latency probe carrying an opaque timestamp token.
   *
   * @param token the token to be echoed back
   * @return the probe message
   */
  public static JSONObject probe(long token) {
    return new JSONObject().put("type", "probe").put("token", token);
  }

  /**
   * Builds the echo response to a probe.
   *
   * @param token the token from the probe
   * @return the echo message
   */
  public static JSONObject echo(long token) {
    return new JSONObject().put("type", "echo").put("token", token);
  }

  /**
   * Builds a graceful session-close message.
   *
   * @return the bye message
   */
  public static JSONObject bye() {
    return new JSONObject().put("type", "bye");
  }
}
