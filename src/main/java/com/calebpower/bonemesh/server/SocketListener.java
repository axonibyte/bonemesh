package com.calebpower.bonemesh.server;

import java.io.IOException;
import java.net.BindException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.LinkedList;
import java.util.List;

import com.calebpower.bonemesh.BoneMesh;

public class SocketListener implements Runnable {
  
  private BoneMesh boneMesh = null;
  private int port = 0;
  private List<Socket> socketPool = null;
  private ServerSocket server = null;
  
  public SocketListener(BoneMesh boneMesh, int port) {
    this.boneMesh = boneMesh;
    this.port = port;
    socketPool = new LinkedList<>();
  }
  
  @Override public void run() {
    try {
      server = new ServerSocket(port, 50);
      this.port = server.getLocalPort();
      System.out.println("Listening to port " + getPort() + ".");
      Socket socket = null;
      
      for(int i = 0; i < 10; i++) {
        System.out.println("Launching instance " + i + " of message handler...");
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
      System.out.println("Unable to bind to port " + port + ".");
    } catch(IOException e) { //rip x2
      System.out.println("Unable to instantiate a server socket on port " + port + ".");
    }
  }
  
  public int getPort() {
    while(server == null) try {
      Thread.sleep(500L);
    } catch(InterruptedException e) { }
    return server.getLocalPort();
  }
  
  public BoneMesh getBoneMesh() {
    return boneMesh;
  }
  
  public List<Socket> getSocketPool() {
    return socketPool;
  }
  
}
