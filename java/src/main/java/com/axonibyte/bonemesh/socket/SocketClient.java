/*
 * Copyright (c) 2019-2022 Axonibyte Innovations, LLC. All rights reserved.
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

package com.axonibyte.bonemesh.socket;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.DelayQueue;

import org.json.JSONException;
import org.json.JSONObject;

import com.axonibyte.bonemesh.BoneMesh;
import com.axonibyte.bonemesh.Logger;
import com.axonibyte.bonemesh.listener.AckListener;
import com.axonibyte.bonemesh.message.AckMessage;
import com.axonibyte.bonemesh.node.Node;

/**
 * Sends out payloads.
 * 
 * @author Caleb L. Power
 */
public class SocketClient implements Runnable {

  private static final int CONNECT_TIMEOUT_MILLIS = 5_000;

  private BoneMesh boneMesh = null;
  private DelayQueue<Payload> payloadQueue = null;
  private Logger logger = null;
  private Thread thread = null;

  private SocketClient(BoneMesh boneMesh, Logger logger) {
    this.boneMesh = boneMesh;
    this.logger = logger;
    this.payloadQueue = new DelayQueue<>();
  }
  
  /**
   * Builds and launches a socket client thread.
   * 
   * @param boneMesh the BoneMesh instance
   * @param logger the logger
   * @return a reference to the new socket client object
   */
  public static SocketClient build(BoneMesh boneMesh, Logger logger) {
    SocketClient socketClient = new SocketClient(boneMesh, logger);
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
        Payload payload = payloadQueue.take(); // blocks until a payload is eligible

        DataInputStream inputStream = null;
        DataOutputStream outputStream = null;
        Node node = boneMesh.getNodeMap().getNodeByLabel(payload.getTarget());

        if(node != null) try(Socket socket = new Socket()) {
          socket.connect(
              new InetSocketAddress(node.getIP(), node.getPort()),
              CONNECT_TIMEOUT_MILLIS);
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
                && AckMessage.isImplementedBy(json)) {
              payload.setAckResponse(json); // listeners read the response, not just the request
              for(AckListener listener : payload.getAckListeners())
                listener.receiveAck(payload);
            }
          } catch(JSONException e) {
            logger.logError("CLIENT", e.getMessage());
          } catch(NullPointerException e) {
            logger.logError("CLIENT", "Client disconnected before sending data.");
          }
          
          inputStream.close();
          outputStream.close();
        } catch(IOException e) {
          logger.logError("CLIENT", String.format("Ran into issues sending data: %1$s", e.getMessage()));
          if(payload.getAckListeners() != null)
            for(AckListener listener : payload.getAckListeners())
              listener.receiveNak(payload);
          if(payload.doRequeueOnFailure()) {
            payload.recordFailure(); // backs the next attempt off; see Payload
            queuePayload(payload);
          }
        }

      }
    } catch(InterruptedException e) { }
  }

  /**
   * Queues up a payload for delivery
   *
   * @param payload the payload with wrapped data
   */
  public void queuePayload(Payload payload) {
    payloadQueue.add(payload);
  }
  
  /**
   * Interrupts the socket client thread.
   */
  public void kill() {
    thread.interrupt();
  }
  
}
