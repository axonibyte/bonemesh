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

package com.axonibyte.bonemesh.v3.transport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * Frame classification tests. The cases mirror the shared corpus
 * (spec/corpus/framing.json); byte-for-byte agreement between this classifier
 * and the Go one over that corpus is additionally checked on the driver by
 * interop/check-framing.sh (see FrameCheck).
 */
public class FrameCodecTest {

  private static byte[] ascii(String s) {
    return s.getBytes(StandardCharsets.US_ASCII);
  }

  private void expectAccept(byte[] raw) {
    FrameCodec.Verdict v = FrameCodec.classify(raw, FrameCodec.TRANSPORT_CAP);
    assertTrue(v.accepted(), "expected accept, got reject(" + v.reason() + ")");
  }

  private void expectReject(byte[] raw, String reason) {
    FrameCodec.Verdict v = FrameCodec.classify(raw, FrameCodec.TRANSPORT_CAP);
    assertFalse(v.accepted(), "expected reject(" + reason + "), got accept");
    assertEquals(reason, v.reason());
  }

  @Test void simpleObjectAccepts() {
    expectAccept(ascii("{\"a\":1}\n"));
  }

  @Test void missingTrailingNewlineRejected() {
    expectReject(ascii("{\"a\":1}"), "no-newline");
  }

  @Test void emptyLineRejected() {
    expectReject(ascii("\n"), "empty");
  }

  @Test void notJsonRejected() {
    expectReject(ascii("not json\n"), "invalid-json");
  }

  @Test void jsonArrayRejectedAsNotAnObject() {
    expectReject(ascii("[1,2,3]\n"), "not-an-object");
  }

  @Test void interiorNewlineSplitsFrameAndFailsJson() {
    // Bytes: {"a": <newline> 1} <newline> — the reader stops at the first
    // newline, leaving the invalid fragment {"a": to parse.
    expectReject(ascii("{\"a\":\n1}\n"), "invalid-json");
  }

  @Test void invalidUtf8Rejected() {
    byte[] raw = new byte[] { '{', '"', 'a', '"', ':', '"', (byte) 0xff, '"', '}', '\n' };
    expectReject(raw, "invalid-utf8");
  }

  @Test void trailingGarbageAfterObjectRejected() {
    expectReject(ascii("{\"a\":1} X\n"), "trailing-data");
  }

  @Test void frameExactlyAtCapAccepts() {
    expectAcceptAtCap(FrameCodec.TRANSPORT_CAP);
  }

  @Test void frameOneByteOverCapIsOversize() {
    byte[] raw = lineOfLength(FrameCodec.TRANSPORT_CAP + 1);
    FrameCodec.Verdict v = FrameCodec.classify(raw, FrameCodec.TRANSPORT_CAP);
    assertFalse(v.accepted());
    assertEquals("oversize", v.reason());
  }

  private void expectAcceptAtCap(int cap) {
    byte[] raw = lineOfLength(cap);
    FrameCodec.Verdict v = FrameCodec.classify(raw, cap);
    assertTrue(v.accepted(), "frame at exactly the cap should accept, got " + v.reason());
  }

  // {"p":"AAA..."} padded so total length including the newline equals n.
  private static byte[] lineOfLength(int n) {
    int fill = n - "{\"p\":\"\"}".length() - 1;
    StringBuilder sb = new StringBuilder("{\"p\":\"");
    for(int i = 0; i < fill; i++) sb.append('A');
    sb.append("\"}\n");
    return sb.toString().getBytes(StandardCharsets.US_ASCII);
  }
}
