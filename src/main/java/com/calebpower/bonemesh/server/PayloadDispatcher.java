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

import com.calebpower.bonemesh.server.ServerNode.SubnetPreference;

public class PayloadDispatcher implements Runnable {
  
  private JSONObject payload = null;
  private ServerNode node = null;
  
  public PayloadDispatcher(ServerNode node, JSONObject payload) {
    this.node = node;
    this.payload = payload;
  }
  
  @Override public void run() {
    BufferedInputStream inputStream = null;
    BufferedOutputStream outputStream = null;
    Socket socket = null;
    
    try {
      System.out.println("SENDING:\n" + payload.toString(2));
      
      for(int failures = 0; failures < 10; failures++) {
        try {
          if(node.getSubnetPreference() == SubnetPreference.UNKNOWN
              || node.getSubnetPreference() == SubnetPreference.LOCAL) {
            socket = new Socket("127.0.0.1", node.getPort());
            node.setSubnetPreference(SubnetPreference.LOCAL);
            System.out.println("Sent to " + node.getName() + "@127.0.0.1:" + node.getPort());
          }
        } catch(IOException e) {
          node.setSubnetPreference(SubnetPreference.UNKNOWN);
        }
        
        try {
          if(node.getSubnetPreference() == SubnetPreference.UNKNOWN
              || node.getSubnetPreference() == SubnetPreference.INTERNAL) {
            socket = new Socket(node.getInternalHost(), node.getPort());
            node.setSubnetPreference(SubnetPreference.INTERNAL);
            System.out.println("Sent to " + node.getName() + "@" + node.getInternalHost() + ":" + node.getPort());
          }
        } catch(IOException e) {
          node.setSubnetPreference(SubnetPreference.UNKNOWN);
        }
        
        try {
          if(node.getSubnetPreference() == SubnetPreference.UNKNOWN
              || node.getSubnetPreference() == SubnetPreference.EXTERNAL) {
            socket = new Socket(node.getExternalHost(), node.getPort());
            node.setSubnetPreference(SubnetPreference.EXTERNAL);
            System.out.println("Sent to " + node.getName() + "@" + node.getExternalHost() + ":" + node.getPort());
          }
        } catch(IOException e) {
          node.setSubnetPreference(SubnetPreference.UNKNOWN);
        }
        
        if(node == null || node.getSubnetPreference() == SubnetPreference.UNKNOWN) {
          System.out.println("Could not deliver the payload to " + node.getName() + "!");
          node.setAlive(false);
          try {
            Thread.sleep(1000L);
          } catch(InterruptedException e) { }
        } else break;
      }
      
      //if(!node.isAlive()) return;
      
      inputStream = new BufferedInputStream(socket.getInputStream());
      outputStream = new BufferedOutputStream(socket.getOutputStream());
      PrintWriter writer = new PrintWriter(outputStream);
      writer.println(payload.toString());
      writer.flush();
      
      BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
      JSONObject response = new JSONObject(reader.readLine());
      
      System.out.println("RECEIVED RESPONSE: " + response.toString());
      
      if(response.has("backbone")
          && response.has("payload")
          && response.getJSONObject("payload").has("status")
          && response.getJSONObject("payload").getString("status").equals("ok"))
        node.setAlive(true);
      else node.setAlive(false);
    } catch (JSONException e) {
      System.out.println("Received bad response.");
    } catch(IOException e) {
      node.setAlive(false);
      System.out.println("Could not connect to server.");
    } finally {
      try {
        socket.close();
      } catch(IOException e) { }
    }
  }

}
