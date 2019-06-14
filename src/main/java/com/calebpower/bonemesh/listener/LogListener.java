package com.calebpower.bonemesh.listener;

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
