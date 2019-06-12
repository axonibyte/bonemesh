package com.calebpower.bonemesh.defunct.server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;

public class ConnectionClient implements Runnable {
  
  private MessageHandler handler = null;
  private String ip = null;
  private int port = 0;
  
  public ConnectionClient(MessageHandler handler, String ip, int port) {
    this.handler = handler;
    this.ip = ip;
    this.port = port;
  }
  
  @Override public void run() {
    try(Socket socket = new Socket(ip, port);
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
      socket.setSoTimeout(0);
      
    } catch(UnknownHostException e) {
      e.printStackTrace();
    } catch(IOException e) {
      e.printStackTrace();
    }
  }
  
}
