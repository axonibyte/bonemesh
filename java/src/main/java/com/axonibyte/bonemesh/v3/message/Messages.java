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
   * Builds an acknowledgement routed back toward the origin (protocol.md
   * &sect;7): {@code to} is the origin, {@code from} is this node.
   *
   * @param mid the id being acknowledged
   * @param from this node's label
   * @param to the origin the ack is routed back toward
   * @param ttl the hop limit for routing the ack back
   * @return the ack message
   */
  public static JSONObject ackTo(String mid, String from, String to, int ttl) {
    return new JSONObject()
        .put("type", "ack").put("mid", mid)
        .put("from", from).put("to", to).put("ttl", ttl);
  }

  /**
   * Builds a negative acknowledgement naming the failing hop and reason (defect
   * D4), routed back toward the origin like a data message (protocol.md &sect;7).
   *
   * @param mid the id that could not be delivered
   * @param from this reporting relay's label
   * @param to the origin the nak is routed back toward
   * @param hop the label of the hop that failed
   * @param reason a short reason (e.g. {@code ttl}, {@code no-route},
   *     {@code link-dead}); not enum-checked on the wire
   * @param ttl the hop limit for routing the nak back
   * @return the nak message
   */
  public static JSONObject nak(String mid, String from, String to, String hop, String reason, int ttl) {
    return new JSONObject()
        .put("type", "nak")
        .put("mid", mid)
        .put("hop", hop)
        .put("reason", reason)
        .put("from", from)
        .put("to", to)
        .put("ttl", ttl);
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
   * Builds a graceful session-close message with no reason.
   *
   * @return the bye message
   */
  public static JSONObject bye() {
    return new JSONObject().put("type", "bye");
  }

  /**
   * Builds a graceful session-close message carrying a reason.
   *
   * @param reason a short reason (e.g. {@code idle}, {@code rekey-failed}); when
   *     {@code null} or empty the reason field is omitted
   * @return the bye message
   */
  public static JSONObject bye(String reason) {
    JSONObject m = new JSONObject().put("type", "bye");
    if(reason != null && !reason.isEmpty()) m.put("reason", reason);
    return m;
  }
}
