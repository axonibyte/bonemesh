package com.calebpower.bonemesh.socket;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

import org.json.JSONException;
import org.json.JSONObject;

import com.calebpower.bonemesh.Logger;
import com.calebpower.bonemesh.message.AckMessage;

public class IncomingSocketHandler implements Runnable {
  
  private Logger logger = null;
  private Socket socket = null;
  private SocketServer server = null;
  private Thread thread = null;
  
  public IncomingSocketHandler(Logger logger) {
    this.logger = logger;
  }
  
  public void handle(Socket socket, SocketServer callback) {
    this.server = callback;
    this.socket = socket;
    thread = new Thread(this);
    thread.setDaemon(true);
    thread.start();
  }
  
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
        server.dispatchToListeners(json);
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
  
  public void kill() {
    thread.interrupt();
  }

}
