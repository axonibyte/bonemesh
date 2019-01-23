package com.calebpower.bonemesh.socket;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;

import com.calebpower.bonemesh.BoneMesh;
import com.calebpower.bonemesh.node.Node;

/**
 * Listens for incoming connections.
 * 
 * @author Caleb L. Power
 */
public class SocketServer implements Runnable {

  private BoneMesh boneMesh = null;
  private int port = 0;
  private Thread thread = null;
  
  /**
   * Overloaded constructor for the server.
   */
  public SocketServer(BoneMesh boneMesh, int port) {
    this.boneMesh = boneMesh;
    this.port = port;
  }
  
  @Override public void run() {
    for(;;) { // keep the server alive
      // Logger.info("Spinning up peer-to-peer server.");
      System.out.println("Spinning up socket server...");
      
      try(ServerSocket serverSocket = new ServerSocket(port)) {
        Socket clientSocket = null;
        while((clientSocket = serverSocket.accept()) != null) {
          System.out.println("Accepted connection from some client.");
          clientSocket.setSoTimeout(0);
          IncomingDataHandler.build(boneMesh, clientSocket);
          // BoneMesh.syncNode(nodeList, new Node().setSocket(clientSocket));
          /*
          this.serverSocket = serverSocket;
          this.clientSocket = clientSocket;
          Logger.info("Peer-to-peer server started on port " + port + ".");
          handler.setOutput(out);
          int input;
          while((input = in.read()) != -1) handler.queue((char)input);
          */
        }
      } catch(IOException e) {
        /*
          if(this.serverSocket != null)
            Logger.error("Exception caught when trying to listen on port "
              + port + " or listening for a connection.");
          gameEngine.startServer();
        */
      }
    }
  }
  
  public SocketServer start() {
    thread = new Thread(this);
    thread.setDaemon(true);
    thread.start();
    return this;
  }
  
  /**
   * Kills the server.
   */
  public void kill() {
    /*
      Logger.info("Killing the peer-to-peer server.");
      if(this.serverSocket != null) {
        ServerSocket serverSocket = this.serverSocket;
        this.serverSocket = null;
        try {
          serverSocket.close();
        } catch(IOException e) { }
      }
      
      if(this.clientSocket != null) {
        Socket clientSocket = this.clientSocket;
        this.clientSocket = null;
        try {
          clientSocket.close();
        } catch(IOException e) { }
      }
    */
    if(thread != null) thread.interrupt();
  }
  
  /**
   * Retrieves the port.
   * 
   * @return the port
   */
  public int getPort() {
    return port;
  }
  
}
