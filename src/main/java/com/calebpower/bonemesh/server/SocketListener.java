package com.calebpower.bonemesh.server;

import java.io.IOException;
import java.net.BindException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.LinkedList;
import java.util.List;

import com.calebpower.bonemesh.BoneMesh;

/**
 * Listens to incoming connections and dispatches aid connections to the
 * appropriate handler(s).
 * 
 * @author Caleb L. Power
 */
public class SocketListener implements Runnable {
  
  private BoneMesh boneMesh = null;
  private int port = 0;
  private List<Socket> socketPool = null;
  private ServerSocket server = null;
  
  /**
   * Overloaded constructor to set the BoneMesh instance and listening port.
   * 
   * @param boneMesh the BoneMesh instance
   * @param port the listening port number
   */
  public SocketListener(BoneMesh boneMesh, int port) {
    this.boneMesh = boneMesh;
    this.port = port;
    socketPool = new LinkedList<>();
  }
  
  @Override public void run() {
    try {
      server = new ServerSocket(port, 50);
      this.port = server.getLocalPort();
      boneMesh.log("Listening to port " + getPort() + ".");
      Socket socket = null;
      
      for(int i = 0; i < 10; i++) {
        boneMesh.log("Launching instance " + i + " of message handler...");
        Thread thread = new Thread(new MessageHandler(this));
        thread.setDaemon(true);
        thread.start();
      }
      
      for(;;) {
        socket = server.accept();
        synchronized(socketPool) {
          socketPool.add(socket);
          socketPool.notifyAll();
        }
        socket = null;
      }
    } catch(BindException e) { //rip
      boneMesh.log("Unable to bind to port " + port + ".");
    } catch(IOException e) { //rip x2
      boneMesh.log("Unable to instantiate a server socket on port " + port + ".");
    }
  }
  
  /**
   * Retrieves the listening port number
   * 
   * @return int representation of the listening port
   */
  public int getPort() {
    while(server == null) try {
      Thread.sleep(500L);
    } catch(InterruptedException e) { }
    return server.getLocalPort();
  }
  
  /**
   * Retrieves the current BoneMesh instance.
   * 
   * @return BoneMesh the BoneMesh instance
   */
  public BoneMesh getBoneMesh() {
    return boneMesh;
  }
  
  /**
   * Retrieves the socket pool.
   * 
   * @return List containing pending sockets
   */
  public List<Socket> getSocketPool() {
    return socketPool;
  }
  
}
