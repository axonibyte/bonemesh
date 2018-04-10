package com.calebpower.bonemesh.server;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.LinkedList;
import java.util.List;

import org.json.JSONException;
import org.json.JSONObject;

import com.calebpower.bonemesh.BoneMesh;
import com.calebpower.bonemesh.message.AckMessage;
import com.calebpower.bonemesh.message.Message.Action;

public class MessageHandler implements Runnable {
  
  private SocketListener socketListener = null;
  
  public MessageHandler(SocketListener socketListener) {
    this.socketListener = socketListener;
  }

  @Override public void run() {
    BoneMesh boneMesh = socketListener.getBoneMesh();
    Socket socket = null;
    
    for(;;) {
      
      synchronized(socketListener.getSocketPool()) {
        while(socketListener.getSocketPool().isEmpty()) {
          try {
            socketListener.getSocketPool().wait();
          } catch(InterruptedException e) {
            continue;
          }
        }
        socket = socketListener.getSocketPool().remove(0);
      }
      
      try {
        socket.setSoTimeout(10000);
        System.out.println("Accepted an incoming message from " + socket.getRemoteSocketAddress().toString() + ".");
        
        DataInputStream inputStream = new DataInputStream(socket.getInputStream());
        DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());
        
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
        JSONObject response = null;
        JSONObject boneMeshObject = null;
        Action action = null;
        
        if(message.has("bonemesh")
            && message
                .getJSONObject("bonemesh")
                .has("action")) {
          boneMeshObject = message.getJSONObject("bonemesh");
          action = Action.valueOf(boneMeshObject.getString("action"));
        }
        
        if(action == null) {
          response = new AckMessage(boneMesh.getThisServer(), false);
        } else {
          
          switch(action) {
            case DEATH:
              boneMesh.unload(boneMeshObject.getString("from"));
              break;
            case DISCOVER: //here take unknown servers and send init requests to each
              //the old one did boneMesh.loadNodes(...)
              break;
            case INIT: //here just straight up load the server, override if necessary
              break;
            case TRANSMIT:
              //TODO do things here
              break;
            default:
              break;
          }
          
          /*
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
          */

          writer.println(response.toString());
          writer.flush();
        
        }
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
  
}
