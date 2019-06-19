package com.calebpower.bonemesh.socket;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.LinkedList;
import java.util.List;

import org.json.JSONException;
import org.json.JSONObject;

import com.calebpower.bonemesh.Logger;
import com.calebpower.bonemesh.listener.AckListener;
import com.calebpower.bonemesh.message.AckMessage;

/**
 * Sends out payloads.
 * 
 * @author Caleb L. Power
 */
public class SocketClient implements Runnable {

  private List<Payload> payloadQueue = null;
  private Logger logger = null;
  private Thread thread = null;
  
  private SocketClient(Logger logger) {
    this.logger = logger;
    this.payloadQueue = new LinkedList<>();
  }
  
  /**
   * Builds and launches a socket client thread.
   * 
   * @param logger the logger
   * @return a reference to the new socket client object
   */
  public static SocketClient build(Logger logger) {
    SocketClient socketClient = new SocketClient(logger);
    socketClient.thread = new Thread(socketClient);
    socketClient.thread.setDaemon(true);
    socketClient.thread.start();
    return socketClient;
  }
  
  /**
   * {@inheritDoc}
   */
  @Override public void run() {
    try {
      for(;;) {
        Payload payload = null;
        synchronized(payloadQueue) {
          if(payloadQueue.size() == 0) {
            payloadQueue.wait();
            continue; // allow for multithreading on the same instance in the future
          }
          payload = payloadQueue.remove(0);
        }
        
        DataInputStream inputStream = null;
        DataOutputStream outputStream = null;
        
        try(Socket socket = new Socket(payload.getTargetIP(), payload.getTargetPort())) {
          inputStream = new DataInputStream(socket.getInputStream());
          outputStream = new DataOutputStream(socket.getOutputStream());
          
          PrintWriter out = new PrintWriter(outputStream);
          logger.logDebug("CLIENT", String.format("Sending data: %1$s", payload.getRawData()));
          out.println(payload.getRawData());
          out.flush();
          
          BufferedReader in = new BufferedReader(new InputStreamReader(inputStream));
          try {
            JSONObject json = new JSONObject(in.readLine());
            logger.logDebug("CLIENT", String.format("Received data: %1$s", json.toString()));
            if(payload.getAckListeners() != null
                && AckMessage.isImplementedBy(json))
              for(AckListener listener : payload.getAckListeners())
                listener.receiveAck(payload);
          } catch(JSONException e) {
            logger.logError("CLIENT", e.getMessage());
          }
          
          inputStream.close();
          outputStream.close();
        } catch(IOException e) {
          logger.logError("CLIENT", String.format("Ran into issues sending data: %1$s", e.getMessage()));
          if(payload.getAckListeners() != null)
            for(AckListener listener : payload.getAckListeners())
              listener.receiveNak(payload);
          if(payload.doRequeueOnFailure()) queuePayload(payload); // try again later
        }
        
      }
    } catch(InterruptedException e) { }
  }
  
  /**
   * Queues up a payload for delivery
   * 
   * @param payload the payload with wrapped data
   */
  public synchronized void queuePayload(Payload payload) {
    synchronized(payloadQueue) {
      payloadQueue.add(payload);
      payloadQueue.notifyAll();
    }
  }
  
  /**
   * Interrupts the socket client thread.
   */
  public void kill() {
    thread.interrupt();
  }
  
}
