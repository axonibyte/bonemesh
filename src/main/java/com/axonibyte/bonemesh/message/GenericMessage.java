/*
 * Copyright (c) 2019 Axonibyte Innovations, LLC. All rights reserved.
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

package com.axonibyte.bonemesh.message;

import com.axonibyte.bonemesh.BoneMesh;
import com.axonibyte.bonemesh.crypto.CryptoEngine;
import com.axonibyte.bonemesh.crypto.CryptoEngine.CryptoException;

import org.bouncycastle.util.encoders.Base64;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * A generic message to be sent in a payload.
 * 
 * @author Caleb L. power
 */
public class GenericMessage extends JSONObject {

  /**
   * Builds a message with a custom action to be dispatched.
   *
   * @param boneMesh the {@link BoneMesh} instance
   * @param from the node from which the message is sent
   * @param to the recipient node
   * @param action the action associated with this message
   * @param payload the payload
   * @return a {@link GenericMessage} object
   * @throws {@link CryptoException} if cryptographic operations failed
   */
  public static GenericMessage build(BoneMesh boneMesh, String from, String to, String action, JSONObject payload)
      throws CryptoException {
    GenericMessage message = new GenericMessage();
    CryptoEngine cryptoEngine = boneMesh.getCryptoEngine();
    if(!cryptoEngine.supportsCrypto(to)) {
      String encapsulated = new String(Base64.encode(cryptoEngine.encapsulate(to)));
      message.put("kex", encapsulated);
    }
    message.put("payload", cryptoEngine.encrypt(to, payload));
    message.put("from", from);
    message.put("to", to);
    message.put("action", null == action ? "generic" : action);
    return message;
  }

  /**
   * Builds a generic message to be dispatched.
   *
   * @param boneMesh the {@link BoneMesh} instance
   * @param from the node from which the message is sent
   * @param to the recipient node
   * @param payload the payload
   * @return a {@link GenericMessage} object
   * @throws {@link CryptoException} if cryptographic operations failed
   */
  public static GenericMessage build(BoneMesh boneMesh, String from, String to, JSONObject payload)
      throws CryptoException {
    return build(boneMesh, from, to, null, payload);
  }
  
  private GenericMessage() { }
  
  /**
   * Overloaded constructor that provides custom action metadata.
   * 
   * @param from the node from which the message is sent
   * @param to the recipient node
   * @param action the custom action denoted in this message
   * @param payload the payload that is to be sent
   */
  protected GenericMessage(String from, String to, String action, JSONObject payload) {
    put("from", from);
    put("to", to);
    put("action", action);
    put("payload", payload == null ? new JSONObject() : payload);
  }
  
  /**
   * Generates a generic message from a JSON object.
   * 
   * @param json the raw JSON object
   * @throws JSONException if there is unexpected data or lack thereof
   */
  public GenericMessage(JSONObject json) throws JSONException {
    put("from", json.getString("from"));
    put("to", json.getString("to"));
    put("action", json.getString("action"));
    try {
      put("payload", json.getJSONObject("payload"));
    } catch(JSONException e) {
      put("payload", json.getString("payload"));
    }
    if(json.has("kex")) setKEX(json.getString("kex"));
  }
  
  /**
   * Determines if an incoming JSON object implements a generic message
   * with no custom action.
   * 
   * @param data the incoming data
   * @return <code>true</code> if the action is of type <code>generic</code>
   */
  public static boolean isImplementedBy(JSONObject data) {
    try {
      return data.getString("action").equals("generic");
    } catch(JSONException e) { }
    return false;
  }
  
  /**
   * Retrieves the sender.
   * 
   * @return String denoting the sender
   */
  public String getFrom() {
    return getString("from");
  }
  
  /**
   * Retrieves the intended target. If message had to be rerouted, then the
   * receiver might be different than the target.
   * 
   * @return String denoting the intended target
   */
  public String getTo() {
    return getString("to");
  }

  /**
   * Determines whether or not the payload is currently encrypted.
   *
   * @return {@code true} iff the payload is encrypted
   */
  public boolean isEncrypted() {
    return get("payload") instanceof String;
  }
  
  /**
   * Retrieves the message payload.
   * 
   * @return JSONObject containing the payload data
   */
  public JSONObject getPayload() {
    return getJSONObject("payload");
  }

  /**
   * Decrypts this message's payload.
   *
   * @param CryptoEngine the cryptography engine to be used to
   *        perform the decryption operation
   * @return {@code true} iff decryption was successful
   */
  public boolean decryptPayload(CryptoEngine cryptoEngine) {
    try {
      put("payload", cryptoEngine.decrypt(getFrom(), getString("payload")));
      return true;
    } catch(CryptoException e) {
      e.printStackTrace();
      return false;
    }
  }
  
  /**
   * Retrieves the message action.
   * 
   * @return String denoting the message action 
   */
  public String getAction() {
    return getString("action");
  }

  /**
   * Determines whether or not this message contains key exchange data.
   *
   * @return {@code true} iff this message contains key exchange data
   */
  public boolean hasKEX() {
    return has("kex");
  }

  /**
   * Retrieves the key exchange data attached to this message.
   *
   * @return Base64 representation of an encapsulated key
   */
  public String getKEX() {
    return getString("kex");
  }

  /**
   * Adds an encapsulated key to the data for use in KEX processing
   * before consuming the payload.
   *
   * @param encapsulated the encapsulated key
   */
  public void setKEX(String encapsulated) {
    put("kex", encapsulated);
  }
}
