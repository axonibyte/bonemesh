package com.calebpower.bonemesh.listener.cheap;

import com.calebpower.bonemesh.listener.LogListener;

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
