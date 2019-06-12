package com.calebpower.bonemesh;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import com.calebpower.bonemesh.listener.LogListener;

public class Logger {
  
  private List<LogListener> listeners = null;
  
  Logger() {
    this.listeners = new CopyOnWriteArrayList<>();
  }
  
  public void addListener(LogListener listener) {
    listeners.add(listener);
  }
  
  public void removeListener(LogListener listener) {
    listeners.remove(listener);
  }
  
  public void logDebug(String label, String message) {
    long now = System.currentTimeMillis();
    for(LogListener listener : listeners)
      listener.onDebug(label, message, now);
  }
  
  public void logInfo(String label, String message) {
    long now = System.currentTimeMillis();
    for(LogListener listener : listeners)
      listener.onInfo(label, message, now);    
  }
  
  public void logError(String label, String message) {
    long now = System.currentTimeMillis();
    for(LogListener listener : listeners)
      listener.onError(label, message, now);
  }
  
}
