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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

/**
 * The BoneMesh v3 frame reader/writer (protocol.md &sect;2): one
 * newline-terminated UTF-8 JSON object per frame, within a hard size cap. This
 * is the enforcement point for defect D7 (unbounded input), and its accept /
 * reject verdicts match the shared corpus (spec/corpus/framing.json) so a Java
 * node and a Go node agree on exactly which frames are well formed.
 *
 * @author Caleb L. Power
 */
public final class FrameCodec {

  /**
   * Maximum handshake frame size, bytes including the newline (protocol.md §0).
   * 32 KiB: post-quantum certificates and signatures are large — a bmx2 message
   * carries an ML-DSA-65 certificate (with a ~4.6 KB ML-DSA-87 root signature)
   * plus a ~3.3 KB transcript signature, all Base64-expanded, near 20 KB.
   */
  public static final int HANDSHAKE_CAP = 32768;
  /** Default maximum transport frame size, bytes including the newline. */
  public static final int TRANSPORT_CAP = 65536;

  private FrameCodec() { }

  /**
   * Classifies the first frame in {@code raw} against a size cap, matching the
   * corpus verdicts. Reads only up to the first newline; bytes after it belong
   * to the next frame.
   *
   * @param raw the bytes as read from the wire
   * @param cap the maximum frame size (including the newline)
   * @return the accepted object, or a rejection with a reason tag
   */
  public static Verdict classify(byte[] raw, int cap) {
    int nl = indexOf(raw, (byte) '\n');
    if(nl < 0) return Verdict.reject("no-newline");
    if(nl + 1 > cap) return Verdict.reject("oversize");
    byte[] content = Arrays.copyOfRange(raw, 0, nl);
    if(content.length == 0) return Verdict.reject("empty");

    String str;
    try {
      str = strictUtf8(content);
    } catch(CharacterCodingException e) {
      return Verdict.reject("invalid-utf8");
    }

    char first = str.charAt(0);
    if(first == '[') return Verdict.reject("not-an-object");
    if(first != '{') return Verdict.reject("invalid-json");

    JSONTokener tokener = new JSONTokener(str);
    JSONObject obj;
    try {
      obj = new JSONObject(tokener);
    } catch(JSONException e) {
      return Verdict.reject("invalid-json");
    }
    if(tokener.nextClean() != 0) return Verdict.reject("trailing-data");
    return Verdict.accept(obj);
  }

  /**
   * Reads one frame from a stream, bounded by {@code cap}.
   *
   * @param in the input stream
   * @param cap the maximum frame size (including the newline)
   * @return the decoded object
   * @throws FrameException if the frame is malformed or exceeds the cap
   * @throws IOException on a stream error, or end of stream before a newline
   */
  public static JSONObject readFrame(InputStream in, int cap) throws FrameException, IOException {
    byte[] buffer = new byte[cap];
    int len = 0;
    for(;;) {
      int b = in.read();
      if(b < 0) throw new IOException("stream ended before a frame newline");
      if(len >= cap) throw new FrameException("oversize");
      buffer[len++] = (byte) b;
      if(b == '\n') break;
    }
    Verdict v = classify(Arrays.copyOfRange(buffer, 0, len), cap);
    if(!v.accepted()) throw new FrameException(v.reason());
    return v.object();
  }

  /**
   * Writes one frame (the object followed by a single newline).
   *
   * @param out the output stream
   * @param object the object to write
   * @param cap the maximum frame size (including the newline)
   * @throws FrameException if the encoded frame would exceed the cap
   * @throws IOException on a stream error
   */
  public static void writeFrame(OutputStream out, JSONObject object, int cap)
      throws FrameException, IOException {
    byte[] body = object.toString().getBytes(StandardCharsets.UTF_8);
    if(body.length + 1 > cap) throw new FrameException("oversize");
    out.write(body);
    out.write('\n');
    out.flush();
  }

  private static String strictUtf8(byte[] bytes) throws CharacterCodingException {
    CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT);
    return decoder.decode(ByteBuffer.wrap(bytes)).toString();
  }

  private static int indexOf(byte[] array, byte target) {
    for(int i = 0; i < array.length; i++) if(array[i] == target) return i;
    return -1;
  }

  /** The outcome of classifying a frame: an accepted object, or a reason. */
  public static final class Verdict {
    private final JSONObject object;
    private final String reason;

    private Verdict(JSONObject object, String reason) {
      this.object = object;
      this.reason = reason;
    }

    static Verdict accept(JSONObject object) {
      return new Verdict(object, null);
    }

    static Verdict reject(String reason) {
      return new Verdict(null, reason);
    }

    /** @return <code>true</code> if the frame was accepted */
    public boolean accepted() {
      return reason == null;
    }

    /** @return the accepted object, or <code>null</code> if rejected */
    public JSONObject object() {
      return object;
    }

    /** @return the rejection reason, or <code>null</code> if accepted */
    public String reason() {
      return reason;
    }
  }

  /** Thrown when a frame is malformed or exceeds its size cap. */
  public static final class FrameException extends Exception {
    FrameException(String message) {
      super(message);
    }
  }
}
