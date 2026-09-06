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

package com.axonibyte.bonemesh.v3.handshake;

import com.axonibyte.bonemesh.v3.cert.Certificate;

/**
 * The result of a completed BMX handshake: the two directional transport keys
 * and the authenticated peer certificate. Send/receive keys are assigned by
 * role so the two directions never share a key or nonce space.
 *
 * @author Caleb L. Power
 */
public final class Session {

  private final byte[] sendKey;
  private final byte[] receiveKey;
  private final Certificate peerCertificate;
  private final byte[] transcriptHash;

  Session(byte[] sendKey, byte[] receiveKey, Certificate peerCertificate, byte[] transcriptHash) {
    this.sendKey = sendKey;
    this.receiveKey = receiveKey;
    this.peerCertificate = peerCertificate;
    this.transcriptHash = transcriptHash;
  }

  /** @return the key this node encrypts outbound transport frames with */
  public byte[] sendKey() {
    return sendKey.clone();
  }

  /** @return the key this node decrypts inbound transport frames with */
  public byte[] receiveKey() {
    return receiveKey.clone();
  }

  /** @return the peer's verified membership certificate */
  public Certificate peerCertificate() {
    return peerCertificate;
  }

  /**
   * @return the final transcript hash of the handshake — a per-session
   *         identifier both ends agree on, used to label key-log entries
   *         (security.md &sect;8)
   */
  public byte[] transcriptHash() {
    return transcriptHash.clone();
  }
}
