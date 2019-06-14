package com.calebpower.bonemesh.socket;

import org.json.JSONObject;

import com.calebpower.bonemesh.listener.AckListener;

/**
 * Wrapper object to wrap user data before sending it.
 * Contains routing metadata.
 * 
 * @author Caleb L. Power
 */
public class Payload {
  
  private boolean requeueOnFailure;
  private int targetPort;
  private AckListener ackListener = null;
  private JSONObject data = null;
  private String targetIP = null;
  
  /**
   * Overloaded constructor.
   * Requeues on routing failure (downed node/server).
   * Does not send acks or naks to callbacks.
   * 
   * @param data the wrapped data
   * @param targetIP the target IP
   * @param targetPort the target port
   */
  public Payload(JSONObject data, String targetIP, int targetPort) {
    this(data, targetIP, targetPort, null);
  }
  
  /**
   * Overloaded constructor.
   * Does not send acks or naks to callbacks.
   * 
   * @param data the wrapped data
   * @param targetIP the target IP
   * @param targetPort the target port
   * @param requeueOnFailure <code>true</code> to requeue on failure
   */
  public Payload(JSONObject data, String targetIP, int targetPort, boolean requeueOnFailure) {
    this(data, targetIP, targetPort, null, requeueOnFailure);
  }
  
  /**
   * Overloaded constructor.
   * Requeues on routing failure (downed node/server).
   * 
   * @param data the wrapped data
   * @param targetIP the target IP
   * @param targetPort the target port
   * @param ackListener an ack/nak listener
   */
  public Payload(JSONObject data, String targetIP, int targetPort, AckListener ackListener) {
    this(data, targetIP, targetPort, ackListener, true);
  }
  
  /**
   * Overloaded constructor.
   * 
   * @param data the wrapped data
   * @param targetIP the target IP
   * @param targetPort the target port
   * @param ackListener an ack/nak listener
   * @param requeueOnFailure <code>true</code> to requeue on failure
   */
  public Payload(JSONObject data, String targetIP, int targetPort, AckListener ackListener, boolean requeueOnFailure) {
    this.data = data;
    this.targetIP = targetIP;
    this.targetPort = targetPort;
    this.ackListener = ackListener;
    this.requeueOnFailure = requeueOnFailure;
  }
  
  /**
   * Retrieves the wrapped data as a JSON object.
   * 
   * @return the data as a JSON object
   */
  public JSONObject getData() {
    return data;
  }
  
  /**
   * Retrieves the wrapped data as a String.
   * 
   * @return the data as a String
   */
  public String getRawData() {
    return data.toString();
  }
  
  /**
   * Retrieves the target IP address.
   * 
   * @return String form of the target's IP address
   */
  public String getTargetIP() {
    return targetIP;
  }
  
  /**
   * Retrieves the target port.
   * 
   * @return the target's listening port number
   */
  public int getTargetPort() {
    return targetPort;
  }
  
  /**
   * Retrieves the ack/nak listener.
   * 
   * @return the ack listener or <code>null</code> if there isn't one
   */
  public AckListener getAckListener() {
    return ackListener;
  }
  
  /**
   * Determines whether or not to requeue if a failure happens.
   * 
   * @return <code>true</code> if the payload needs to be queued again
   */
  public boolean doRequeueOnFailure() {
    return requeueOnFailure;
  }
  
}
