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

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.json.JSONObject;

import com.axonibyte.bonemesh.v3.crypto.Aead;
import com.axonibyte.bonemesh.v3.handshake.Session;

/**
 * The encrypted transport channel over a completed handshake (protocol.md
 * &sect;4): each frame is a sequence-numbered AEAD carrier
 * <code>{"seq":n,"ct":"&lt;base64&gt;"}</code> whose plaintext is the inner
 * JSON message. The per-direction sequence counter is the AEAD nonce (4 zero
 * bytes then the 64-bit little-endian counter), so it is never reused and a
 * reordered or replayed frame is rejected.
 *
 * @author Caleb L. Power
 */
public final class TransportSession {

  private static final Base64.Encoder B64ENC = Base64.getEncoder();
  private static final Base64.Decoder B64DEC = Base64.getDecoder();

  private byte[] sendKey;
  private byte[] receiveKey;
  private long sendSeq;
  private long receiveSeq;

  /**
   * Wraps a completed handshake session.
   *
   * @param session the completed handshake session
   */
  public TransportSession(Session session) {
    this.sendKey = session.sendKey();
    this.receiveKey = session.receiveKey();
  }

  /** @return the per-direction send counter (for deciding when to rekey, F5) */
  public synchronized long sendSeq() {
    return sendSeq;
  }

  /** @return the per-direction receive counter */
  public synchronized long receiveSeq() {
    return receiveSeq;
  }

  /**
   * Installs a new outbound key and resets the send counter to 0, at the rekey
   * boundary immediately after the last old-key frame in this direction has
   * been sealed (F5).
   *
   * @param key the new 32-byte send key
   */
  public synchronized void swapSend(byte[] key) {
    this.sendKey = key;
    this.sendSeq = 0;
  }

  /**
   * Installs a new inbound key and resets the receive counter, immediately
   * after opening the last old-key frame in this direction (F5).
   *
   * @param key the new 32-byte receive key
   */
  public synchronized void swapReceive(byte[] key) {
    this.receiveKey = key;
    this.receiveSeq = 0;
  }

  /**
   * Seals an inner message into a transport frame body (a JSON object; the
   * caller frames it with {@link FrameCodec}).
   *
   * @param inner the inner message
   * @return the <code>{seq, ct}</code> carrier object
   */
  public synchronized JSONObject seal(JSONObject inner) {
    long seq = sendSeq++;
    byte[] ct = sealCiphertext(sendKey, seq, inner.toString().getBytes(StandardCharsets.UTF_8));
    return new JSONObject().put("seq", seq).put("ct", B64ENC.encodeToString(ct));
  }

  /**
   * Seals a transport-frame ciphertext under a key and sequence number, the
   * single implementation of the transport envelope AEAD (empty AAD, the
   * sequence-derived nonce). Used by {@link #seal(JSONObject)} and by the
   * cross-language transport-frame vector.
   *
   * @param key the 32-byte direction key
   * @param seq the sequence number (also the nonce input)
   * @param plaintext the inner message bytes
   * @return the ciphertext with appended tag
   */
  public static byte[] sealCiphertext(byte[] key, long seq, byte[] plaintext) {
    return Aead.seal(key, nonce(seq), new byte[0], plaintext);
  }

  /**
   * Opens a transport frame body, enforcing in-order delivery (the frame's
   * sequence must equal the next expected one) and authenticity.
   *
   * @param carrier the <code>{seq, ct}</code> object
   * @return the recovered inner message
   * @throws TransportException if the sequence is out of order or the tag fails
   */
  public synchronized JSONObject open(JSONObject carrier) throws TransportException {
    long seq = carrier.getLong("seq");
    if(seq != receiveSeq)
      throw new TransportException("out-of-order frame: expected seq " + receiveSeq + ", got " + seq);
    byte[] ct = B64DEC.decode(carrier.getString("ct"));
    byte[] plaintext;
    try {
      plaintext = Aead.open(receiveKey, nonce(seq), new byte[0], ct);
    } catch(Aead.AeadException e) {
      throw new TransportException("frame authentication failed: " + e.getMessage());
    }
    receiveSeq++;
    return new JSONObject(new String(plaintext, StandardCharsets.UTF_8));
  }

  // Nonce = 4 zero bytes || 64-bit little-endian counter (the same convention
  // as the handshake key schedule).
  private static byte[] nonce(long seq) {
    byte[] n = new byte[Aead.NONCE_BYTES];
    for(int i = 0; i < 8; i++) n[4 + i] = (byte) (seq >>> (8 * i));
    return n;
  }

  /** Thrown when a transport frame is out of order or fails authentication. */
  public static final class TransportException extends Exception {
    TransportException(String message) {
      super(message);
    }
  }
}
