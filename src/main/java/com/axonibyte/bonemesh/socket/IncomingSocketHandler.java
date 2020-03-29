/*
 * Copyright (c) 2019 Axonibyte Innovations, LLC. All rights reserved.
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
import java.net.Socket;

import org.json.JSONException;
import org.json.JSONObject;

import com.axonibyte.bonemesh.BoneMesh;
import com.axonibyte.bonemesh.Logger;
import com.axonibyte.bonemesh.message.AckMessage;
import com.axonibyte.bonemesh.message.DiscoveryMessage;
import com.axonibyte.bonemesh.message.GenericMessage;
import com.axonibyte.bonemesh.node.Node;

/**
 * Handles incoming data.
 * 
 * @author Caleb L. Power
 */
public class IncomingSocketHandler implements Runnable {
  
  private BoneMesh boneMesh = null;
  private Logger logger = null;
  private Socket socket = null;
  private SocketServer server = null;
  private Thread thread = null;
  
  /**
   * Overloaded constructor.
   * 
   * @param boneMesh the BoneMesh instance
   * @param logger the logger
   */
  public IncomingSocketHandler(BoneMesh boneMesh, Logger logger) {
    this.boneMesh = boneMesh;
    this.logger = logger;
  }
  
  /**
   * Launches a thread to handle the socket.
   * 
   * @param socket the incoming socket
   * @param callback a callback to the socket server
   */
  public void handle(Socket socket, SocketServer callback) {
    this.server = callback;
    this.socket = socket;
    thread = new Thread(this);
    thread.setDaemon(true);
    thread.start();
  }
  
  /**
   * {@inheritDoc}
   */
  @Override public void run() {
    DataInputStream inputStream = null;
    DataOutputStream outputStream = null;
    
    try {
      inputStream = new DataInputStream(socket.getInputStream());
      outputStream = new DataOutputStream(socket.getOutputStream());
      
      BufferedReader in = new BufferedReader(new InputStreamReader(inputStream));
      JSONObject json = new JSONObject(in.readLine());
      logger.logDebug("HANDLER", String.format("Received data: %1$s", json.toString()));
      if(!AckMessage.isImplementedBy(json)) {
        AckMessage ack = new AckMessage(json);
        if(DiscoveryMessage.isImplementedBy(json)) {
          DiscoveryMessage message = new DiscoveryMessage(json); // deserialize discovery message
          Node node = boneMesh.getNodeByLabel(message.getFrom());
          boneMesh.getNodeMap().setNodeNeighbors(message.getFrom(), message.getNodes());
          if(node == null) {
            node = new Node(message.getFrom(),
                socket.getInetAddress().toString(),
                message.getPort());
            boneMesh.getNodeMap().addOrReplaceNode(node, true);
          } else {
            node.setIP(socket.getInetAddress().toString())
                .setPort(message.getPort());
          }
          // TODO here, save new nodes if necessary
          // make sure to pass the appropriate IP address
          
        } else {
          GenericMessage message = new GenericMessage(json); // attempt to deserialize message
          System.out.println("!!!!!!!!!!!! " + message.getTo() + " -> " + boneMesh.getInstanceLabel());
          if(boneMesh.getInstanceLabel().equalsIgnoreCase(message.getTo())) // intended for us?
            server.dispatchToListeners(json); // yes, dispatch to listeners
          else boneMesh.sendDatum(message.getTo(), json, false); // no, send to appropriate location
        }
        PrintWriter out = new PrintWriter(outputStream);
        logger.logDebug("HANDLER", String.format("Sending data: %1$s", ack.toString()));
        out.println(ack);
        out.flush();
      }
    } catch(JSONException | IOException e) {
      logger.logError("HANDLER", e.getMessage());
    }
    server.killHandler(this);
  }
  
  /**
   * Interrupts the thread for this handler instance.
   */
  public void kill() {
    thread.interrupt();
  }

}
