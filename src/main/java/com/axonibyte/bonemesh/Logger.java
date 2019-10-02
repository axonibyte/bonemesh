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

package com.axonibyte.bonemesh;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import com.axonibyte.bonemesh.listener.LogListener;

/**
 * Simple BoneMesh logging class.
 * 
 * @author Caleb L. Power
 */
public class Logger {
  
  private List<LogListener> listeners = null;
  
  /**
   * Null constructor.
   */
  public Logger() {
    this.listeners = new CopyOnWriteArrayList<>();
  }
  
  /**
   * Adds a log listener.
   * 
   * @param listener the listener
   */
  public void addListener(LogListener listener) {
    listeners.add(listener);
  }
  
  /**
   * Removes a particular log listener.
   * 
   * @param listener the listener.
   */
  public void removeListener(LogListener listener) {
    listeners.remove(listener);
  }
  
  /**
   * Logs a debug message.
   * 
   * @param label the message tag
   * @param message the message
   */
  public void logDebug(String label, String message) {
    long now = System.currentTimeMillis();
    for(LogListener listener : listeners)
      listener.onDebug(label, message, now);
  }
  
  /**
   * Logs an informational message.
   * 
   * @param label the message tag
   * @param message the message
   */
  public void logInfo(String label, String message) {
    long now = System.currentTimeMillis();
    for(LogListener listener : listeners)
      listener.onInfo(label, message, now);    
  }
  
  /**
   * Logs an error.
   * 
   * @param label the message tag
   * @param message the message
   */
  public void logError(String label, String message) {
    long now = System.currentTimeMillis();
    for(LogListener listener : listeners)
      listener.onError(label, message, now);
  }
  
}
