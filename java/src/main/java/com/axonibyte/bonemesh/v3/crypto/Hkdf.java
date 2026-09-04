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

package com.axonibyte.bonemesh.v3.crypto;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

/**
 * HKDF-SHA-256 (RFC 5869), the BoneMesh v3 key-derivation function
 * (security.md &sect;11). Full extract-then-expand, matching any conforming
 * implementation, so the BMX key schedule derives identical keys across
 * languages.
 *
 * @author Caleb L. Power
 */
public final class Hkdf {

  private Hkdf() { }

  /**
   * Derives {@code length} bytes via HKDF-SHA-256 (extract with {@code salt},
   * expand with {@code info}).
   *
   * @param salt the salt (may be empty, not null)
   * @param ikm the input key material
   * @param info the context/application info (may be empty, not null)
   * @param length the number of output bytes
   * @return the derived output key material
   */
  public static byte[] derive(byte[] salt, byte[] ikm, byte[] info, int length) {
    HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
    hkdf.init(new HKDFParameters(ikm, salt, info));
    byte[] out = new byte[length];
    hkdf.generateBytes(out, 0, length);
    return out;
  }
}
