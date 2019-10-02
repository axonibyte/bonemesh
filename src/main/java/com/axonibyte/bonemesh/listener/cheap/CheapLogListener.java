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

package com.axonibyte.bonemesh.listener.cheap;

import com.axonibyte.bonemesh.listener.LogListener;

/**
 * Quick implementation of the log listener.
 * 
 * @author Caleb L. Power
 */
public class CheapLogListener implements LogListener {
  
  /**
   * {@inheritDoc}
   */
  @Override public void onDebug(String label, String message, long timestamp) {
    System.out.printf("[DEBUG:%1$s %2$s] %3$s\n", label, Long.toString(timestamp), message);
  }
  
  /**
   * {@inheritDoc}
   */
  @Override public void onInfo(String label, String message, long timestamp) {
    System.out.printf("[INFO:%1$s %2$s] %3$s\n", label, Long.toString(timestamp), message);
  }

  /**
   * {@inheritDoc}
   */
  @Override public void onError(String label, String message, long timestamp) {
    System.out.printf("[ERROR:%1$s %2$s] %3$s\n", label, Long.toString(timestamp), message);
  }

}
