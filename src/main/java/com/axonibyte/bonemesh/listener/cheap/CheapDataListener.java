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

import org.json.JSONObject;

import com.axonibyte.bonemesh.Logger;
import com.axonibyte.bonemesh.listener.DataListener;

/**
 * Quick implementation of the data listener.
 * 
 * @author Caleb L. power
 */
public class CheapDataListener implements DataListener {
  
  private Logger logger = null;
  
  /**
   * Overloaded constructor.
   * 
   * @param logger the logger
   */
  public CheapDataListener(Logger logger) {
    this.logger = logger;
  }
  
  /**
   * {@inheritDoc}
   */
  @Override public void digest(JSONObject message) {
    logger.logDebug("CHEAP_DATA_LISTENER", String.format("Caught message '%1$s'", message));
  }

}
