package com.calebpower.bonemesh.socket;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.logging.Logger;

import com.calebpower.bonemesh.node.Node;

/**
 * Connects to an external machine to establish a P2P connection.
 * 
 * @author Caleb L. Power
 */
public class SocketClient implements Callable<Node> {

  private int port = 0;
  private String ip = null;
  private Socket socket = null;
  
  /**
   * Overloaded constructor for the client.
   */
  public SocketClient(String ip, int port) {
    this.ip = ip;
    this.port = port;
    System.out.println("Calling out to server momentarily.");
  }
  
  @Override public Node call() {
    Node node = null;
    
    System.out.println("Attempting to connect to some server...");
    
    try(Socket socket = new Socket(ip, port)) {
      socket.setSoTimeout(0);
      /*
      synchronized(connectionStatus) {
        connectionStatus.setStatus(ConnectionStatus.Status.LIVE_CONNECTION);
        connectionStatus.notifyAll();
      }
      */
      node = new Node().setSocket(socket).start(); //add socket here
      // Logger.info("Peer-to-peer client pointed to " + ip + ":" + port);
      // handler.setOutput(out);
      // int input;
      // while((input = in.read()) != -1) handler.queue((char)input);
    } catch(UnknownHostException e) {
      /*
        synchronized(connectionStatus) {
          connectionStatus.setStatus(ConnectionStatus.Status.EXCEPTION_THROWN);
          connectionStatus.notifyAll();
        }
        Logger.error("Peer-to-peer client couldn't get any information about " + ip);
      */
    } catch(IOException e) {
      /*
        synchronized(connectionStatus) {
          connectionStatus.setStatus(ConnectionStatus.Status.EXCEPTION_THROWN);
          connectionStatus.notifyAll();
        }
        Logger.error("Peer-to-peer client couldn't get I/O for the connection to " + ip);
      */
    }
    
    return node;
  }
  
  /**
   * Retrieves the target IP and port
   * 
   * @return String representation of the target IP and port
   */
  public String getTarget() {
    return ip + ":" + port;
  }
  
}
