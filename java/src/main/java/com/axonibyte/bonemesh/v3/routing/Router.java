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

package com.axonibyte.bonemesh.v3.routing;

import org.json.JSONObject;

/**
 * Applies the routing decision to an inbound data message (protocol.md
 * &sect;6-7): deliver it locally, forward it to the next hop with a decremented
 * {@code ttl}, or fail it. Failures name the responsible hop, which is the
 * substance of defect D4's fix — a relay failure is attributed to the next hop
 * that could not carry the message, never to the final destination it was bound
 * for.
 *
 * @author Caleb L. Power
 */
public final class Router {

  private final String selfLabel;
  private final RoutingTable table;

  /**
   * @param selfLabel this node's label
   * @param table the routing table
   */
  public Router(String selfLabel, RoutingTable table) {
    this.selfLabel = selfLabel;
    this.table = table;
  }

  /**
   * Decides what to do with a data message.
   *
   * @param dataMessage the inbound data message
   * @return the routing decision
   */
  public Decision route(JSONObject dataMessage) {
    String to = dataMessage.getString("to");
    if(to.equalsIgnoreCase(selfLabel)) return Decision.deliver();

    int ttl = dataMessage.getInt("ttl") - 1;
    if(ttl <= 0) return Decision.dropTtl();

    String nextHop = table.nextHop(to);
    if(nextHop == null) return Decision.unreachable(to);

    JSONObject forwarded = new JSONObject(dataMessage.toString()).put("ttl", ttl);
    return Decision.forward(nextHop, forwarded);
  }

  /** What to do with a routed message. */
  public static final class Decision {

    /** The kind of routing outcome. */
    public enum Action {
      /** The message is for this node; hand it to listeners. */
      DELIVER,
      /** Forward the message to {@link #nextHop()}. */
      FORWARD,
      /** The hop limit reached zero; drop and NAK. */
      DROP_TTL,
      /** No route to the destination; drop and NAK. */
      UNREACHABLE
    }

    private final Action action;
    private final String nextHop;
    private final JSONObject message;

    private Decision(Action action, String nextHop, JSONObject message) {
      this.action = action;
      this.nextHop = nextHop;
      this.message = message;
    }

    static Decision deliver() {
      return new Decision(Action.DELIVER, null, null);
    }

    static Decision forward(String nextHop, JSONObject message) {
      return new Decision(Action.FORWARD, nextHop, message);
    }

    static Decision dropTtl() {
      return new Decision(Action.DROP_TTL, null, null);
    }

    static Decision unreachable(String dest) {
      return new Decision(Action.UNREACHABLE, dest, null);
    }

    /** @return the routing action */
    public Action action() {
      return action;
    }

    /** @return the next-hop neighbor for FORWARD (the hop a NAK names on failure) */
    public String nextHop() {
      return nextHop;
    }

    /** @return the message to forward (ttl already decremented) for FORWARD */
    public JSONObject message() {
      return message;
    }
  }
}
