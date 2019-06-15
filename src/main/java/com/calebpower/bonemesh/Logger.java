package com.calebpower.bonemesh;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import com.calebpower.bonemesh.listener.LogListener;

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
