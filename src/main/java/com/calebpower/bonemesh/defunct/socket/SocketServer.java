package com.calebpower.bonemesh.defunct.socket;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

import org.json.JSONObject;

import com.calebpower.bonemesh.defunct.BoneMesh;
import com.calebpower.bonemesh.defunct.tx.GenericTx;
import com.calebpower.bonemesh.defunct.tx.GenericTx.TxType;

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
        serverSocket.setSoTimeout(0);
        while((clientSocket = serverSocket.accept()) != null) {
          //PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
          //out.println(new GenericTx(boneMesh.getUUID(), null, TxType.GENERIC_TX,
            //new JSONObject().put("message", "MSG A FROM " + boneMesh.getIdentifier())).toString());
          //out.println(new GenericTx(boneMesh.getUUID(), null, TxType.GENERIC_TX,
              //new JSONObject().put("message", "MSG B FROM " + boneMesh.getIdentifier())).toString());
          System.out.println("Accepted connection from some client.");
          clientSocket.setKeepAlive(true);
          clientSocket.setSoTimeout(0);
          clientSocket.setTcpNoDelay(true);
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
        System.out.println("In SocketServer.java: " + e.getMessage());
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