package com.calebpower.bonemesh.socket;

import org.json.JSONObject;

import com.calebpower.bonemesh.listener.AckListener;

public class Payload {
  
  private boolean requeueOnFailure;
  private int targetPort;
  private AckListener ackListener = null;
  private JSONObject data = null;
  private String targetIP = null;
  
  public Payload(JSONObject data, String targetIP, int targetPort) {
    this(data, targetIP, targetPort, null);
  }
  
  public Payload(JSONObject data, String targetIP, int targetPort, boolean requeueOnFailure) {
    this(data, targetIP, targetPort, null, requeueOnFailure);
  }
  
  public Payload(JSONObject data, String targetIP, int targetPort, AckListener ackListener) {
    this(data, targetIP, targetPort, ackListener, true);
  }
  
  public Payload(JSONObject data, String targetIP, int targetPort, AckListener ackListener, boolean requeueOnFailure) {
    this.data = data;
    this.targetIP = targetIP;
    this.targetPort = targetPort;
    this.ackListener = ackListener;
    this.requeueOnFailure = requeueOnFailure;
  }
  
  public JSONObject getData() {
    return data;
  }
  
  public String getRawData() {
    return data.toString();
  }
  
  public String getTargetIP() {
    return targetIP;
  }
  
  public int getTargetPort() {
    return targetPort;
  }
  
  public AckListener getAckListener() {
    return ackListener;
  }
  
  public boolean doRequeueOnFailure() {
    return requeueOnFailure;
  }
  
}
