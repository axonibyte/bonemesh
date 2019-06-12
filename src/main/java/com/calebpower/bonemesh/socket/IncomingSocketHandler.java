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

import com.calebpower.bonemesh.message.AckMessage;

public class IncomingSocketHandler implements Runnable {
  
  private Socket socket = null;
  private SocketServer server = null;
  private Thread thread = null;
  
  public void handle(Socket socket, SocketServer callback) {
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
      System.out.printf("SERVER RECEIVED DATA: %1$s\n", json.toString());
      if(!AckMessage.isImplementedBy(json)) {
        AckMessage ack = new AckMessage(json);
        server.dispatchToListeners(json);
        PrintWriter out = new PrintWriter(outputStream);
        System.out.printf("SERVER SENT DATA: %1$s\n", ack.toString());
        out.println(ack);
        out.flush();
      }
    } catch(JSONException | IOException e) {
      e.printStackTrace();
    }
    server.killHandler(this);
  }
  
  public void kill() {
    thread.interrupt();
  }

}
