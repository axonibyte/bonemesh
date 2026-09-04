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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * JCS canonicalization tests. The vectors here mirror the shared corpus
 * (spec/corpus/canon.json) and security.md §11.1; byte-identity between this
 * canonicalizer and the Go one over the shared corpus is additionally checked
 * by interop/check-canon.sh (see CanonDump).
 */
public class JcsTest {

  private static String canon(Map<String, Object> m) {
    return new String(Jcs.canonicalize(m), StandardCharsets.UTF_8);
  }

  private static Map<String, Object> cert(Object... kv) {
    Map<String, Object> m = new LinkedHashMap<>();
    for(int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
    return m;
  }

  @Test void basicSortedKeys() {
    assertEquals(
        "{\"exp\":1790000000,\"idk\":\"YWJj\",\"label\":\"alpha\",\"mesh\":\"acme-prod\",\"nbf\":1788500000,\"v\":3}",
        canon(cert("v", 3L, "mesh", "acme-prod", "label", "alpha",
            "idk", "YWJj", "nbf", 1788500000L, "exp", 1790000000L)));
  }

  @Test void nonAsciiEmittedRawUtf8() {
    assertEquals(
        "{\"exp\":1,\"idk\":\"AA==\",\"label\":\"café\",\"mesh\":\"m\",\"nbf\":0,\"v\":3}",
        canon(cert("v", 3L, "mesh", "m", "label", "café",
            "idk", "AA==", "nbf", 0L, "exp", 1L)));
  }

  @Test void stringEscapingQuoteBackslash() {
    assertEquals(
        "{\"exp\":1,\"idk\":\"AA==\",\"label\":\"a\\\"b\\\\c\",\"mesh\":\"m\",\"nbf\":0,\"v\":3}",
        canon(cert("v", 3L, "mesh", "m", "label", "a\"b\\c",
            "idk", "AA==", "nbf", 0L, "exp", 1L)));
  }

  // Control characters, built from bytes: 'a', U+0001, TAB, 'b'. U+0001 escapes
  // to the six-character backslash-u form; TAB to its two-character short form.
  @Test void controlCharsShortAndUForms() {
    String label = new String(new byte[] { 'a', 0x01, 0x09, 'b' }, StandardCharsets.UTF_8);
    StringBuilder want = new StringBuilder("{\"exp\":1,\"idk\":\"AA==\",\"label\":\"a");
    want.append('\\').append("u0001");
    want.append('\\').append('t');
    want.append("b\",\"mesh\":\"m\",\"nbf\":0,\"v\":3}");
    assertEquals(want.toString(),
        canon(cert("v", 3L, "mesh", "m", "label", label,
            "idk", "AA==", "nbf", 0L, "exp", 1L)));
  }

  @Test void negativeIntegerIsRejected() {
    assertThrows(IllegalArgumentException.class,
        () -> Jcs.canonicalize(cert("v", 3L, "nbf", -1L)));
  }
}
