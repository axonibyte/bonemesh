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

package com.axonibyte.bonemesh.v3.cert;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The BoneMesh restricted-JCS certificate canonicalization (security.md
 * &sect;11.1): the exact byte string the mesh root signs. This is deliberately
 * byte-for-byte identical to the Go {@code canon} package and the shared
 * {@code spec/corpus/canon.json} vectors — cross-language signature
 * verification depends on it.
 *
 * <p>A certificate contains only JSON strings and non-negative integers, so
 * this is a small subset of RFC 8785: sorted keys, minimal escaping, integers
 * in shortest form. (Java {@link String#compareTo} already orders by UTF-16
 * code unit, which is exactly what the profile requires.)</p>
 *
 * @author Caleb L. Power
 */
public final class Jcs {

  private Jcs() { }

  /**
   * Canonicalizes a certificate value map (values must be {@link String} or
   * {@link Long}; nested {@link Map}s are permitted for generality).
   *
   * @param object the value map, already stripped of any {@code sig} member
   * @return the canonical UTF-8 bytes
   */
  public static byte[] canonicalize(Map<String, Object> object) {
    StringBuilder sb = new StringBuilder();
    encodeObject(sb, object);
    return sb.toString().getBytes(StandardCharsets.UTF_8);
  }

  private static void encodeObject(StringBuilder sb, Map<String, Object> object) {
    List<String> keys = new ArrayList<>(object.keySet());
    keys.sort(null); // natural String order == UTF-16 code-unit order
    sb.append('{');
    for(int i = 0; i < keys.size(); i++) {
      if(i > 0) sb.append(',');
      String key = keys.get(i);
      encodeString(sb, key);
      sb.append(':');
      encodeValue(sb, object.get(key));
    }
    sb.append('}');
  }

  @SuppressWarnings("unchecked")
  private static void encodeValue(StringBuilder sb, Object value) {
    if(value instanceof String) {
      encodeString(sb, (String) value);
    } else if(value instanceof Long || value instanceof Integer) {
      long n = ((Number) value).longValue();
      if(n < 0) throw new IllegalArgumentException("certificate integers must be non-negative: " + n);
      sb.append(Long.toString(n));
    } else if(value instanceof Map) {
      encodeObject(sb, (Map<String, Object>) value);
    } else {
      throw new IllegalArgumentException(
          "value type " + (value == null ? "null" : value.getClass().getName())
          + " is not permitted in a certificate");
    }
  }

  private static void encodeString(StringBuilder sb, String s) {
    sb.append('"');
    for(int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch(c) {
        case '"':  sb.append("\\\""); break;
        case '\\': sb.append("\\\\"); break;
        case '\b': sb.append("\\b");  break;
        case '\t': sb.append("\\t");  break;
        case '\n': sb.append("\\n");  break;
        case '\f': sb.append("\\f");  break;
        case '\r': sb.append("\\r");  break;
        default:
          if(c < 0x20) sb.append(String.format("\\u%04x", (int) c));
          else sb.append(c);
      }
    }
    sb.append('"');
  }
}
