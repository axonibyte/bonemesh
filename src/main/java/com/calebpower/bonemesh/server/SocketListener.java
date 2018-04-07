package com.calebpower.bonemesh.server;

import java.io.IOException;
import java.net.BindException;
import java.net.ServerSocket;
import java.net.Socket;

import com.calebpower.bonemesh.BoneMesh;

public class SocketListener implements Runnable {
  
  private BoneMesh boneMesh = null;
  private int port = 0;
  private ServerSocket server = null;
  
  public SocketListener(BoneMesh boneMesh, int port) {
    this.boneMesh = boneMesh;
    this.port = port;
  }
  
  @Override public void run() {
    try {
      server = new ServerSocket(port);
      Socket socket = null;
      
      for(;;) {
        socket = server.accept();
        System.out.println("Accepted an incoming message.");
        Thread thread = new Thread(new MessageHandler(boneMesh, socket));
        thread.setDaemon(true);
        thread.start();
      }
    } catch(BindException e) { //rip
      System.out.println("Unable to bind to port " + port + ".");
    } catch(IOException e) { //rip x2
      System.out.println("Unable to instantiate a server socket on port " + port + ".");
    }
  }
  
  public int getPort() {
    return server.getLocalPort();
  }
  
}
