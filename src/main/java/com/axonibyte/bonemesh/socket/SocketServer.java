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

import java.io.IOException;
import java.net.BindException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.json.JSONObject;

import com.axonibyte.bonemesh.BoneMesh;
import com.axonibyte.bonemesh.Logger;
import com.axonibyte.bonemesh.listener.DataListener;

/**
 * Accepts incoming sockets and sends them to the handler.
 * 
 * @author Caleb L. Power
 */
public class SocketServer implements Runnable {
  
  private int port;
  private BoneMesh boneMesh = null;
  private List<DataListener> dataListeners = null;
  private List<IncomingSocketHandler> handlers = null;
  private Logger logger = null;
  private ServerSocket serverSocket = null;
  private Thread thread = null;
  
  private SocketServer(BoneMesh boneMesh, Logger logger, int port) {
    this.port = port;
    this.dataListeners = new CopyOnWriteArrayList<>();
    this.handlers = new CopyOnWriteArrayList<>();
    this.logger = logger;
    this.boneMesh = boneMesh;
  }
  
  /**
   * Builds and launches a socket server thread.
   * 
   * @param boneMesh the BoneMesh instance
   * @param logger the logger
   * @param port the listening port
   * @return a reference to the new socket server object
   */
  public static SocketServer build(BoneMesh boneMesh, Logger logger, int port) {
    SocketServer socketServer = new SocketServer(boneMesh, logger, port);
    socketServer.thread = new Thread(socketServer);
    socketServer.thread.setDaemon(true);
    socketServer.thread.start();
    return socketServer;
  }
  
  /**
   * {@inheritDoc}
   */
  @Override public void run() {
    while(!thread.isInterrupted()) { // keep the server alive
      try {
        serverSocket = new ServerSocket(port);
        logger.logInfo("SERVER", String.format("Opened on port %1$d", port));
        Socket socket = null;
        serverSocket.setSoTimeout(0);
        while((socket = serverSocket.accept()) != null) {
          logger.logDebug("SERVER", String.format("Accepted socket connection from %1$s",
              socket.getInetAddress().getHostAddress()));
          IncomingSocketHandler handler = new IncomingSocketHandler(boneMesh, logger);
          handlers.add(handler);
          handler.handle(socket, this);
        }
      } catch(BindException e) {
        logger.logError("SERVER", e.getMessage());
        throw new RuntimeException(e);
      } catch(IOException e) {
        logger.logError("SERVER", e.getMessage());
      }
      
      if(serverSocket != null) try {
        serverSocket.close();
      } catch(IOException e) { }
    }
  }
  
  /**
   * Dispatches received messages to the listeners.
   * Called exclusively by handlers.
   * 
   * @param json the payload.
   */
  public void dispatchToListeners(JSONObject json) {
    for(DataListener listener : dataListeners)
      listener.digest(json); // potentially blocking, TODO fix later
  }
  
  /**
   * Kills a particular handler.
   * 
   * @param handler the handler
   */
  public void killHandler(IncomingSocketHandler handler) {
    handlers.remove(handler);
  }
  
  /**
   * Kills all handlers and this socket server thread.
   */
  public void kill() {
    thread.interrupt();
    if(serverSocket != null) try {
      serverSocket.close();
    } catch(IOException e) { }
    for(IncomingSocketHandler handler : handlers)
      handler.kill();
  }
  
  /**
   * Adds a data listener to the workflow.
   * 
   * @param listener the data listener
   */
  public void addDataListener(DataListener listener) {
    dataListeners.add(listener);
  }
  
  /**
   * Removes a particular data listener from the workflow.
   * 
   * @param listener the data listener
   */
  public void removeDataListener(DataListener listener) {
    dataListeners.remove(listener);
  }
}
