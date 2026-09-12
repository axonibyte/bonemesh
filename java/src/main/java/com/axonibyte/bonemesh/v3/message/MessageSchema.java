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
   * @param name one of {@code bmx1}, {@code bmx2}, {@code bmx3},
   *     {@code envelope}, {@code data}, {@code ack}, {@code nak}, {@code bye},
   *     {@code disco}, {@code probe}, {@code echo}, {@code rekey}
   * @param frame the message object
   * @return {@code null} if valid, otherwise a short reason tag
   */
  public static String validate(String name, JSONObject frame) {
    switch(name) {
      case "bmx1":     return validateBmx1(frame);
      case "bmx2":     return validateBmx2(frame);
      case "bmx3":     return validateBmx3(frame);
      case "envelope": return validateEnvelope(frame);
      case "data":     return validateData(frame);
      case "ack":      return validateAck(frame);
      case "nak":      return validateNak(frame);
      case "bye":      return validateBye(frame);
      case "disco":    return validateDisco(frame);
      case "probe":    return validateProbe(frame);
      case "echo":     return validateEcho(frame);
      case "rekey":    return validateRekey(frame);
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
    return checkChunking(f);
  }

  /**
   * Checks the splitting half of the data schema (protocol.md &sect;6.1): the
   * shape of {@code chunk}, its bounds, and the rule that exactly one of
   * {@code payload} and {@code seg} is present.
   *
   * <p>The exclusion is the load-bearing part. It is what stops a node that does
   * not reassemble from handing a fragment to the application as though it were
   * a whole message -- the silent corruption D11 described. A segment has no
   * {@code payload} to deliver, so the mistake is unavailable rather than merely
   * forbidden.</p>
   *
   * <p>Carrying neither stays {@code missing-field} rather than becoming a
   * splitting error: it is an absent field, the corpus has pinned that reason
   * since 3.0.0, and renaming it here would have silently rewritten a vector
   * rather than added one.</p>
   *
   * @param f the data message
   * @return null when valid, else the failure reason
   */
  private static String checkChunking(JSONObject f) {
    int n = 1;
    if(f.has("chunk")) {
      if(!(f.opt("chunk") instanceof JSONObject)) return "chunk-format";
      JSONObject chunk = f.getJSONObject("chunk");
      if(!(chunk.opt("i") instanceof Integer) || !(chunk.opt("n") instanceof Integer))
        return "chunk-format";
      n = chunk.getInt("n");
      int i = chunk.getInt("i");
      if(n < 1 || n > Chunker.MAX_CHUNKS) return "chunk-range";
      if(i < 0 || i >= n) return "chunk-range";
    }
    boolean hasPayload = f.has("payload");
    boolean hasSeg = f.has("seg");
    if(!hasPayload && !hasSeg) return "missing-field";
    // Three clauses, none redundant. A fourth -- an explicit "both present" test
    // -- was here and was deleted: mutation showed it could not reject anything
    // the two below do not already reject, since n is always 1 or more, so it
    // was a check that read as coverage while asserting nothing.
    if(n == 1 && hasSeg) return "payload-or-seg";    // a whole message carries its payload
    if(n > 1 && hasPayload) return "payload-or-seg"; // a segment does not
    if(hasSeg && !(f.opt("seg") instanceof String)) return "seg-format";
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

  // Handshake messages 2 and 3 (security.md §4). Both carry one sealed `auth`
  // member rather than separate cert and sig; bmx2 additionally carries the
  // responder's ephemeral and the KEM ciphertext in the clear.
  private static String validateBmx2(JSONObject f) {
    if(!"bmx2".equals(f.optString("t", null))) return "type";
    return requireBase64(f, "e", "ct", "auth");
  }

  private static String validateBmx3(JSONObject f) {
    if(!"bmx3".equals(f.optString("t", null))) return "type";
    return requireBase64(f, "auth");
  }

  // Route advertisement (protocol.md §4.2, §6): destination label to advertised
  // path cost in milliseconds. An empty advertisement is {}, never [].
  private static String validateDisco(JSONObject f) {
    if(!"disco".equals(f.optString("type", null))) return "type";
    if(!f.has("routes")) return "missing-field";
    if(!(f.opt("routes") instanceof JSONObject)) return "routes-format";
    JSONObject routes = f.getJSONObject("routes");
    for(String k : routes.keySet()) {
      Object v = routes.opt(k);
      if(!(v instanceof Integer) && !(v instanceof Long)) return "routes-format";
      if(((Number) v).longValue() < 0) return "routes-format";
    }
    return null;
  }

  // Latency measurement pair (§4.2, §5). The token is opaque to the responder,
  // which echoes it back unchanged, so only its type is constrained.
  private static String validateProbe(JSONObject f) {
    return validateTokenCarrier(f, "probe");
  }

  private static String validateEcho(JSONObject f) {
    return validateTokenCarrier(f, "echo");
  }

  private static String validateTokenCarrier(JSONObject f, String type) {
    if(!type.equals(f.optString("type", null))) return "type";
    if(!f.has("token")) return "missing-field";
    Object t = f.opt("token");
    if(!(t instanceof Integer) && !(t instanceof Long)) return "token-format";
    return null;
  }

  // Tunneled BMX rekey (§4.2, security.md §6). Phases 1-3 carry the BMX bytes in
  // `body`; phase 4 carries no BMX message and must omit it. That exclusion is
  // the part worth validating: a phase 4 with a body, or a phase 2 without one,
  // means the two sides disagree about where in the exchange they are.
  private static String validateRekey(JSONObject f) {
    if(!"rekey".equals(f.optString("type", null))) return "type";
    String midReason = checkMid(f.opt("mid"));
    if(midReason != null) return midReason;
    if(!f.has("phase")) return "missing-field";
    if(!(f.opt("phase") instanceof Integer)) return "phase-range";
    int phase = f.getInt("phase");
    if(phase < 1 || phase > 4) return "phase-range";
    boolean hasBody = f.has("body");
    if(phase == 4) return hasBody ? "body-or-phase" : null;
    if(!hasBody) return "body-or-phase";
    return checkBase64(f.opt("body"));
  }

  // Every named member must be present and Base64.
  private static String requireBase64(JSONObject f, String... keys) {
    for(String k : keys) {
      if(!f.has(k)) return "missing-field";
      String r = checkBase64(f.opt(k));
      if(r != null) return r;
    }
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
