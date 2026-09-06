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

import java.util.Base64;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * Validates BoneMesh v3 message objects against the pinned schemas
 * (protocol.md &sect;4, security.md &sect;4). Deliberately mirrors the Go
 * conformance runner's {@code schema} package, reason tag for reason tag, so a
 * Java node and a Go node agree on exactly which messages are well formed
 * (proven against the shared spec/corpus/messages.json).
 *
 * @author Caleb L. Power
 */
public final class MessageSchema {

  private MessageSchema() { }

  /**
   * Validates a message against a named schema.
   *
   * @param name one of {@code bmx1}, {@code envelope}, {@code data}, {@code ack},
   *     {@code nak}, {@code bye}
   * @param frame the message object
   * @return {@code null} if valid, otherwise a short reason tag
   */
  public static String validate(String name, JSONObject frame) {
    switch(name) {
      case "bmx1":     return validateBmx1(frame);
      case "envelope": return validateEnvelope(frame);
      case "data":     return validateData(frame);
      case "ack":      return validateAck(frame);
      case "nak":      return validateNak(frame);
      case "bye":      return validateBye(frame);
      default:         return "unknown-schema";
    }
  }

  private static String validateBmx1(JSONObject f) {
    if(!"bmx1".equals(f.optString("t", null))) return "type";
    if(f.optInt("v", -1) != 3) return "version";
    String mesh = f.optString("mesh", null);
    if(mesh == null || mesh.isEmpty()) return "empty-mesh";
    for(String k : new String[] { "e", "k", "n" }) {
      if(!f.has(k)) return "missing-field";
      String r = checkBase64(f.opt(k));
      if(r != null) return r;
    }
    return null;
  }

  private static String validateEnvelope(JSONObject f) {
    if(!f.has("seq")) return "missing-field";
    long seq;
    try {
      seq = f.getLong("seq");
    } catch(JSONException e) {
      return "missing-field";
    }
    if(seq < 0) return "seq-range";
    if(!f.has("ct")) return "missing-field";
    return checkBase64(f.opt("ct"));
  }

  private static String validateData(JSONObject f) {
    if(!"data".equals(f.optString("type", null))) return "type";
    String midReason = checkMid(f.opt("mid"));
    if(midReason != null) return midReason;
    if(!(f.opt("to") instanceof String)) return "missing-field";
    if(!(f.opt("from") instanceof String)) return "missing-field";
    if(!f.has("ttl")) return "missing-field";
    int ttl;
    try {
      ttl = f.getInt("ttl");
    } catch(JSONException e) {
      return "missing-field";
    }
    if(ttl < 1 || ttl > 255) return "ttl-range";
    if(!f.has("payload")) return "missing-field";
    return null;
  }

  private static String validateAck(JSONObject f) {
    if(!"ack".equals(f.optString("type", null))) return "type";
    return checkMid(f.opt("mid"));
  }

  // A NAK is routed back toward the origin like data (to/from/ttl), naming the
  // failing hop and a reason. The reason string is required but not enum-checked,
  // so a future reason value is not a wire break (protocol.md §8).
  private static String validateNak(JSONObject f) {
    if(!"nak".equals(f.optString("type", null))) return "type";
    String midReason = checkMid(f.opt("mid"));
    if(midReason != null) return midReason;
    if(!(f.opt("hop") instanceof String) || ((String) f.opt("hop")).isEmpty()) return "missing-field";
    if(!(f.opt("reason") instanceof String) || ((String) f.opt("reason")).isEmpty()) return "missing-field";
    if(!(f.opt("to") instanceof String)) return "missing-field";
    if(!(f.opt("from") instanceof String)) return "missing-field";
    if(!f.has("ttl")) return "missing-field";
    int ttl;
    try {
      ttl = f.getInt("ttl");
    } catch(JSONException e) {
      return "missing-field";
    }
    if(ttl < 1 || ttl > 255) return "ttl-range";
    return null;
  }

  // A graceful session-close control — link-local, so only its type is required;
  // an optional reason string is not validated further.
  private static String validateBye(JSONObject f) {
    if(!"bye".equals(f.optString("type", null))) return "type";
    return null;
  }

  private static String checkBase64(Object v) {
    if(!(v instanceof String)) return "not-base64";
    try {
      Base64.getDecoder().decode((String) v);
    } catch(IllegalArgumentException e) {
      return "not-base64";
    }
    return null;
  }

  // A 32-character lowercase-hex message id (protocol.md §0).
  private static String checkMid(Object v) {
    if(!(v instanceof String)) return "mid-format";
    String s = (String) v;
    if(s.length() != 32) return "mid-format";
    for(int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if(!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return "mid-format";
    }
    return null;
  }
}
