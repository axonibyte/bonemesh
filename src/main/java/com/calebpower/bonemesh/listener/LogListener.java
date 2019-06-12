package com.calebpower.bonemesh.listener;

public interface LogListener {
  
  public void onDebug(String label, String message, long timestamp);
  public void onInfo(String label, String message, long timestamp);
  public void onError(String label, String message, long timestamp);
  
}
