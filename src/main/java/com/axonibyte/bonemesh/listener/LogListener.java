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

package com.axonibyte.bonemesh.listener;

/**
 * Interface to implement actions upon log entry reception.
 * 
 * @author Caleb L. Power
 */
public interface LogListener {
  
  /**
   * Acts on a debugging message.
   * 
   * @param label the message tag
   * @param message the message
   * @param timestamp the time at which the message was received,
   *        measured in 'milliseconds from the UNIX epoch'
   */
  public void onDebug(String label, String message, long timestamp);
  
  /**
   * Acts on an informational message.
   * 
   * @param label the message tag
   * @param message the message
   * @param timestamp the time at which the message was received,
   *        measured in 'milliseconds from the UNIX epoch'
   */
  public void onInfo(String label, String message, long timestamp);
  
  /**
   * Acts on an error message.
   * 
   * @param label the message tag
   * @param message the message
   * @param timestamp the time at which the message was received,
   *        measured in 'milliseconds from the UNIX epoch'
   */
  public void onError(String label, String message, long timestamp);
  
}
