package com.calebpower.bonemesh.server;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

import org.json.JSONException;
import org.json.JSONObject;

import com.calebpower.bonemesh.BoneMesh;
import com.calebpower.bonemesh.server.ServerNode.SubnetPreference;

/**
 * Responsible for dispatching various payloads.
 * 
 * @author Caleb L. Power
 */
public class PayloadDispatcher implements Runnable {
  
  private BoneMesh boneMesh = null;
  private JSONObject payload = null;
  private ServerNode node = null;
  
  /**
   * Overloaded constructor to initialize the payload dispatcher.
   * 
   * @param boneMesh BoneMesh instance
   * @param node the target node
   * @param payload the payload to deliver
   */
  public PayloadDispatcher(BoneMesh boneMesh, ServerNode node, JSONObject payload) {
    this.boneMesh = boneMesh;
    this.node = node;
    this.payload = payload;
  }
  
  @Override public void run() {
    BufferedInputStream inputStream = null;
    BufferedOutputStream outputStream = null;
    Socket socket = null;
    
    try {
      for(int failures = 0; ; failures++) {
        
        try {
          if(node.getSubnetPreference() == SubnetPreference.UNKNOWN
              || node.getSubnetPreference() == SubnetPreference.LOCAL) {
            socket = new Socket("127.0.0.1", node.getPort());
            node.setSubnetPreference(SubnetPreference.LOCAL);
            boneMesh.log("Sending data to " + node.getName() + "@127.0.0.1:" + node.getPort());
          }
        } catch(IOException e) {
          node.setSubnetPreference(SubnetPreference.UNKNOWN);
        }
        
        try {
          if(node.getSubnetPreference() == SubnetPreference.UNKNOWN
              || node.getSubnetPreference() == SubnetPreference.INTERNAL) {
            socket = new Socket(node.getInternalHost(), node.getPort());
            node.setSubnetPreference(SubnetPreference.INTERNAL);
            boneMesh.log("Sending data to " + node.getName() + "@" + node.getInternalHost() + ":" + node.getPort());
          }
        } catch(IOException e) {
          node.setSubnetPreference(SubnetPreference.UNKNOWN);
        }
        
        try {
          if(node.getSubnetPreference() == SubnetPreference.UNKNOWN
              || node.getSubnetPreference() == SubnetPreference.EXTERNAL) {
            socket = new Socket(node.getExternalHost(), node.getPort());
            node.setSubnetPreference(SubnetPreference.EXTERNAL);
            boneMesh.log("Sent to " + node.getName() + "@" + node.getExternalHost() + ":" + node.getPort());
          }
        } catch(IOException e) {
          node.setSubnetPreference(SubnetPreference.UNKNOWN);
        }
        
        if(node == null || node.getSubnetPreference() == SubnetPreference.UNKNOWN) {
          boneMesh.log("Could not deliver the payload to " + node.getName() + "!");
          if(!boneMesh.isLoaded(node)) return;
          node.setAlive(false);
          try {
            Thread.sleep(1000L);
          } catch(InterruptedException e) { }
        } else {
          node.setAlive(true);
          break;
        }
      }
      
      inputStream = new BufferedInputStream(socket.getInputStream());
      outputStream = new BufferedOutputStream(socket.getOutputStream());
      PrintWriter writer = new PrintWriter(outputStream);
      writer.println(payload.toString());
      writer.flush();
      
      BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
      JSONObject response = new JSONObject(reader.readLine());
      
      if(response.has("bonemesh")
          && response.has("payload")
          && response.getJSONObject("payload").has("status")
          && response.getJSONObject("payload").getString("status").equals("ok"))
        node.setAlive(true);
      else
        node.setAlive(false);
    } catch (JSONException e) {
      boneMesh.log("Received bad response.");
    } catch(IOException e) {
      node.setAlive(false);
      boneMesh.log("Could not connect to server.");
    } finally {
      try {
        if(socket != null) socket.close();
      } catch(IOException e) { }
    }
  }

}
