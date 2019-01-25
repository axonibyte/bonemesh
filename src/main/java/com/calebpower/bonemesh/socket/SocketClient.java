package com.calebpower.bonemesh.socket;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.concurrent.Callable;

import com.calebpower.bonemesh.BoneMesh;
import com.calebpower.bonemesh.node.Node;
import com.calebpower.bonemesh.tx.PingTx;

/**
 * Connects to an external machine to establish a P2P connection.
 * 
 * @author Caleb L. Power
 */
public class SocketClient implements Runnable {

  private BoneMesh boneMesh = null;
  private int port = 0;
  private String ip = null;
  private Socket socket = null;
  
  /**
   * Overloaded constructor for the client.
   */
  private SocketClient(BoneMesh boneMesh, String ip, int port) {
    this.boneMesh = boneMesh;
    this.ip = ip;
    this.port = port;
    System.out.println("Calling out to server momentarily.");
  }
  
  @Override public void run() {
    System.out.println("Attempting to connect to some server...");
    
    try(Socket socket = new Socket(ip, port)) {
      socket.setSoTimeout(0);
      /*
      synchronized(connectionStatus) {
        connectionStatus.setStatus(ConnectionStatus.Status.LIVE_CONNECTION);
        connectionStatus.notifyAll();
      }
      */
      // node = new Node().setSocket(socket).start(); //add socket here
      
      IncomingDataHandler incomingDataHandler = IncomingDataHandler.build(boneMesh, socket);
      incomingDataHandler.send(new PingTx(boneMesh.getUUID(), null, boneMesh.getIdentifier()));
      
      // Logger.info("Peer-to-peer client pointed to " + ip + ":" + port);
      // handler.setOutput(out);
      // int input;
      // while((input = in.read()) != -1) handler.queue((char)input);
    } catch(UnknownHostException e) {
      e.printStackTrace();
      /*
        synchronized(connectionStatus) {
          connectionStatus.setStatus(ConnectionStatus.Status.EXCEPTION_THROWN);
          connectionStatus.notifyAll();
        }
        Logger.error("Peer-to-peer client couldn't get any information about " + ip);
      */
    } catch(IOException e) {
      e.printStackTrace();
      /*
        synchronized(connectionStatus) {
          connectionStatus.setStatus(ConnectionStatus.Status.EXCEPTION_THROWN);
          connectionStatus.notifyAll();
        }
        Logger.error("Peer-to-peer client couldn't get I/O for the connection to " + ip);
      */
    }
  }
  
  /**
   * Retrieves the target IP and port
   * 
   * @return String representation of the target IP and port
   */
  public String getTarget() {
    return ip + ":" + port;
  }
  
  public static SocketClient build(BoneMesh boneMesh, String ip, int port) {
    SocketClient socketClient = new SocketClient(boneMesh, ip, port);
    Thread thread = new Thread(socketClient);
    thread.setDaemon(true);
    thread.start();
    return socketClient;
  }
  
}
