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

package com.axonibyte.bonemesh.socket;

import java.util.ArrayList;
import java.util.List;

import org.json.JSONObject;

import com.axonibyte.bonemesh.listener.AckListener;

/**
 * Wrapper object to wrap user data before sending it.
 * Contains routing metadata.
 * 
 * @author Caleb L. Power
 */
public class Payload {
  
  private boolean requeueOnFailure;
  private List<AckListener> ackListeners = null;
  private JSONObject data = null;
  private String target = null;
  
  /**
   * Overloaded constructor.
   * Requeues on routing failure (downed node/server).
   * Does not send acks or naks to callbacks.
   * 
   * @param data the wrapped data
   * @param target the target node
   */
  public Payload(JSONObject data, String target) {
    this(data, target, (List<AckListener>)null);
  }
  
  /**
   * Overloaded constructor.
   * Does not send acks or naks to callbacks.
   * 
   * @param data the wrapped data
   * @param target the target node
   * @param requeueOnFailure <code>true</code> to requeue on failure
   */
  public Payload(JSONObject data, String target, boolean requeueOnFailure) {
    this(data, target, (List<AckListener>)null, requeueOnFailure);
  }

  /**
   * Overloaded constructor.
   * Requeues on routing failure (downed node/server).
   * 
   * @param data the wrapped data
   * @param target the target node
   * @param ackListener an ack/nak listener
   */
  public Payload(JSONObject data, String target, AckListener ackListener) {
    this(data, target, ackListener, true);
  }
  
  /**
   * Overloaded constructor.
   * Requeues on routing failure (downed node/server).
   * 
   * @param data the wrapped data
   * @param target the target node
   * @param ackListeners an ack/nak listener
   */
  public Payload(JSONObject data, String target, List<AckListener> ackListeners) {
    this(data, target, ackListeners, true);
  }
  
  /**
   * Overloaded constructor.
   * 
   * @param data the wrapped data
   * @param target the target node
   * @param ackListener an ack/nak listener
   * @param requeueOnFailure <code>true</code> to requeue on failure
   */
  public Payload(JSONObject data, String target, AckListener ackListener, boolean requeueOnFailure) {
    List<AckListener> ackListeners = new ArrayList<>();
    ackListeners.add(ackListener);
    this.data = data;
    this.target = target;
    this.ackListeners = ackListeners;
    this.requeueOnFailure = requeueOnFailure;
  }
  
  /**
   * Overloaded constructor.
   * 
   * @param data the wrapped data
   * @param target the target node
   * @param ackListeners ack/nak listeners
   * @param requeueOnFailure <code>true</code> to requeue on failure
   */
  public Payload(JSONObject data, String target, List<AckListener> ackListeners, boolean requeueOnFailure) {
    this.data = data;
    this.target = target;
    this.ackListeners = ackListeners;
    this.requeueOnFailure = requeueOnFailure;
  }
  
  /**
   * Retrieves the wrapped data as a JSON object.
   * 
   * @return the data as a JSON object
   */
  public JSONObject getData() {
    return data;
  }
  
  /**
   * Retrieves the wrapped data as a String.
   * 
   * @return the data as a String
   */
  public String getRawData() {
    return data.toString();
  }

  /**
   * Retrieves the ack/nak listeners.
   * 
   * @return the ack listeners or <code>null</code> if there aren't any
   */
  public List<AckListener> getAckListeners() {
    return ackListeners;
  }
  
  /**
   * Determines whether or not to requeue if a failure happens.
   * 
   * @return <code>true</code> if the payload needs to be queued again
   */
  public boolean doRequeueOnFailure() {
    return requeueOnFailure;
  }
  
  /**
   * Retrieves the label of the target node.
   * 
   * @return the target node's label
   */
  public String getTarget() {
    return target;
  }
  
}
