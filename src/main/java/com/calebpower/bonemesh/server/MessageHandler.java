package com.calebpower.bonemesh.server;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.LinkedList;
import java.util.List;

import org.json.JSONException;
import org.json.JSONObject;

import com.calebpower.bonemesh.BoneMesh;

public class MessageHandler implements Runnable {
  
  private BoneMesh boneMesh = null;
  private Socket socket = null;
  
  public MessageHandler(BoneMesh boneMesh, Socket socket) {
    this.boneMesh = boneMesh;
    this.socket = socket;
  }

  @Override public void run() {
    try {
      socket.setSoTimeout(10000);
      System.out.println("Accepted an incoming message from " + socket.getRemoteSocketAddress().toString() + ".");
      
      BufferedInputStream inputStream = new BufferedInputStream(socket.getInputStream());
      BufferedOutputStream outputStream = new BufferedOutputStream(socket.getOutputStream());
      
      BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
      PrintWriter writer = new PrintWriter(outputStream);
      
      List<Byte> buffer = new LinkedList<>();
      int braceCount = 0;
      do {
        int i = reader.read();
        if(i == '{') braceCount++;
        else if(i == '}') braceCount--;
        buffer.add((byte)i);
      } while(braceCount > 0);
      
      byte[] payload = new byte[buffer.size()];
      for(int i = 0; i < buffer.size(); i++)
        payload[i] = buffer.get(i);
      JSONObject message = new JSONObject(new String(payload));
      JSONObject response = new JSONObject();
      
      //System.out.println("Incoming message:");
      //System.out.println(message.toString(2));
      
      JSONObject boneMeshObject = message.getJSONObject("bonemesh");
      if(boneMeshObject.has("action") && boneMeshObject.getString("action").equals("init")) {
        boneMesh.loadNodes(boneMeshObject.getJSONArray("nodes"));
        response.put("backbone", new JSONObject()
            .put("status", "ok"));
      } else if(boneMeshObject.has("action") && boneMeshObject.getString("action").equals("die")) {
        boneMesh.unload(boneMeshObject.getString("node"));
        response.put("backbone", new JSONObject()
            .put("status", "ok"));
      } else if(boneMeshObject.has("action") && boneMeshObject.getString("action").equals("ack")) {
        System.out.println("Received ACK message.");
        if(boneMesh.getNode(boneMeshObject.getString("node")) != null)
          response.put("backbone", new JSONObject()
              .put("status", "ok"));
      } else {
        ServerNode serverNode = boneMesh.getNode(boneMeshObject.getString("node"));
        response.put("backbone", new JSONObject()
            .put("status", "ok"));
        if(serverNode != null) {
          for(String key : boneMesh.getListeners().keySet()) {
            if(response.has(key)) continue;
            response.put(key, boneMesh.getListeners().get(key).reactToJSON(message));
          }
        }
      }

      writer.println(response.toString());
      writer.flush();
    } catch(JSONException e) {
      //System.out.println("Bad JSON request came through.");
      e.printStackTrace();
    } catch(IOException e) {
      System.out.println("Some IOException was thrown in the message handler.");
      e.printStackTrace();
    } finally {
      try {
        socket.close();
      } catch(IOException e) { }
    }
  }
  
}
