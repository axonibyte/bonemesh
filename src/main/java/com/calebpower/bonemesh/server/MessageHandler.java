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
import com.calebpower.bonemesh.listener.BoneMeshDataListener;
import com.calebpower.bonemesh.message.AckMessage;
import com.calebpower.bonemesh.message.DiscoveryMessage;
import com.calebpower.bonemesh.message.InitRequest;
import com.calebpower.bonemesh.message.Message.Action;

/**
 * Handles incoming messages.
 * 
 * @author Caleb L. Power
 */
public class MessageHandler implements Runnable {
  
  private SocketListener socketListener = null;
  
  /**
   * Overloaded constructor to initialize the message handler.
   * 
   * @param socketListener the socket listener
   */
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
        boneMesh.log("Accepted an incoming message from " + socket.getRemoteSocketAddress().toString() + ".");
        
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
        JSONObject payloadObject = null;
        Action action = null;
        
        if(message.has("bonemesh")
            && message
                .getJSONObject("bonemesh")
                .has("action")) {
          boneMeshObject = message.getJSONObject("bonemesh");
          action = Action.valueOf(boneMeshObject.getString("action"));
          
          if(message.has("payload"))
            payloadObject = message.getJSONObject("payload");
        }
        
        if(action == null) {
          response = new AckMessage(boneMesh.getThisServer(), false);
        } else {
          response = new AckMessage(boneMesh.getThisServer(), true);
          switch(action) {
          case ACK:
            boneMesh.log("Received acknowledgement from " + boneMeshObject.getString("from") +
                " (status = " + payloadObject.getString("status") + ")");
          case DEATH:
            boneMesh.unload(boneMeshObject.getString("from"));
            break;
          case DISCOVER: //here take unknown servers and send init requests to each
            boneMesh.loadNodes(payloadObject.getJSONArray("nodes"));
            break;
          case INIT: //here just straight up load the server, override if necessary
            boneMesh.loadNode(boneMeshObject.getString("from"), payloadObject);
            boneMesh.dispatchToAll(new DiscoveryMessage(boneMesh.getThisServer(), boneMesh.getKnownNodes()));
            break;
          case TRANSMIT:
            boneMesh.log("Transmission received from " + boneMeshObject.getString("from") + ".");
            String listenerID = payloadObject.has("listenerID") ? payloadObject.getString("listenerID") : null;
            for(BoneMeshDataListener dataListener : boneMesh.getDataListeners())
              if(dataListener.eavesdrop() || listenerID == null || dataListener.getID().equals(listenerID))
                dataListener.reactToJSON(message);
            break;
          case WELFARE:
            boneMesh.log("Received welfare check from "
                + (boneMeshObject.has("from") ? boneMeshObject.getString("from") : "an unknown server") + ".");
            if(boneMeshObject.has("from") && boneMesh.getNode(boneMeshObject.getString("from")) == null) {
              boneMesh.dispatch(new InitRequest(boneMesh.getThisServer()),
                  new ServerNode(boneMesh,
                      boneMeshObject.getString("from"),
                      payloadObject.getString("externalHost"),
                      payloadObject.getString("internalHost"),
                      payloadObject.getInt("port"),
                      false));
            }
          }

          writer.println(response.toString());
          writer.flush();
        }
      } catch(JSONException e) {
        boneMesh.log("Bad JSON request came through. " + e.getMessage());
      } catch(IOException e) {
        boneMesh.log("Some IOException was thrown in the message handler. " + e.getMessage());
      } finally {
        try {
          socket.close();
        } catch(IOException e) { }
      }
      
    }
    

  }
  
}
