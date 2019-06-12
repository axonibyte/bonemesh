package com.calebpower.bonemesh.defunct.exception;

import org.json.JSONObject;

public class BadTxException extends Exception {
  
  public BadTxException() {
    super("Unknown exception thrown during transaction processing.");
  }
  
  public BadTxException(String message) {
    super(message);
  }
  
  public BadTxException(JSONObject json, String message) {
    super("Some exception thrown during transaction processing. "
        + "(Additional information: " + message + ", "
        + "Data: " + json.toString() + ").");
  }
  
}
