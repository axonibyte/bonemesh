package com.calebpower.bonemesh.node;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import org.json.JSONException;
import org.json.JSONObject;

public class Node implements Runnable {
  
  private int curlyCount = 0;
  private int port = 0;
  private int previousCurlyCount = 0;
  private BufferedReader input = null;
  private List<Character> incomingData = null;
  private List<Character> dataBuffer = null;
  // private List<Edge> edges = null; // this is implemented in a higher level of the hierarchy
  private Long lastMessageTimestamp = 0L; // timestamp of last message received
  private Long pingTimestamp = 0L; // timestamp of last ping transmission
  private Long pingLatency = 0L; // difference between last ping transmission and answer
  private PrintWriter output = null;
  private String informalName = null;
  private String ip = null;
  private Thread myThread = null;
  private UUID uuid = null;
  
  public Node() {
    // this.edges = new CopyOnWriteArrayList<>();
    this.incomingData = new LinkedList<>();
    this.dataBuffer = new LinkedList<>();
  }
  
  @Override public void run() { // this should only be invoked if we have a direct connection to it
    new Thread(new IncomingDataListener()).start();
    
    try {
      // Logger.info("Spinning up a message handler.");
      for(;;) {
        char current;
        synchronized(incomingData) {
          while(incomingData.isEmpty()) {
            incomingData.wait();
          }
          current = incomingData.remove(0);
        }
        
        if(previousCurlyCount == 0 && curlyCount == 0 && current != '{') continue;
        
        switch(current) {
        case '{':
          previousCurlyCount = curlyCount++;
          dataBuffer.add(current);
          break;
        case '}':
          previousCurlyCount = curlyCount--;
        default:
          dataBuffer.add(current);
        }
        
        if(curlyCount == 0) {
          if(previousCurlyCount == 1) {
            previousCurlyCount = 0;
            
            char[] characters = new char[dataBuffer.size()];
            for(int i = 0; i < dataBuffer.size(); i++)
              characters[i] = dataBuffer.get(i);
            
            try {
              JSONObject jsonObject = new JSONObject(new String(characters));
              
              /*
                Logger.info("Received data: " + jsonObject.toString());
                
                if(!jsonObject.has("status")) { //assume "status" means that it's a response
                  // TODO implement interaction with the game board
                  SocketMessage message = SocketMessage.generate(gameEngine, jsonObject);
                  JSONObject response = message.execute(enableProcessing).waitForResponse();
                  
                  send(response);
                }
              */
              
              lastMessageTimestamp = System.currentTimeMillis();
              System.out.println(jsonObject.toString());
              
              if(!jsonObject.has("status")) send(new JSONObject()
                  .put("status", "ok")
                  .put("data", jsonObject));
                
            } catch(JSONException e) {
              // Logger.error("Some JSONException was thrown in the peer-to-peer connection handler. " + e.getMessage());
              send(new JSONObject()
                  .put("status", "error")
                  .put("message", "syntax error: " + e.getMessage()));
            }
            
            dataBuffer.clear();
            
          } else { //Some syntax error.
            // Logger.error("Some JSONException was thrown in the peer-to-peer connection handler (mismatched curly braces).");
            System.out.println("Got some syntax error.");
            send(new JSONObject()
                .put("status", "error")
                .put("message", "syntax error: mismatched curly braces"));
            continue;
          }
        }
      }
    } catch(InterruptedException e) { }
  }
  
  /**
   * Queue a character for analysis.
   * 
   * @param datum the character
   */
  public synchronized void queue(char datum) {
    synchronized(incomingData) {
      incomingData.add(datum);
      incomingData.notifyAll();
    }
  }
  
  /**
   * Sets the output PrintWriter.
   * 
   * @param output PrintWriter for the output stream
   */
  public synchronized void setOutput(PrintWriter output) {
    if(this.output == null) this.output = output;
    else {
      synchronized(this.output) {
        this.output = output;
      }
    }
  }
  
  public synchronized Node setSocket(Socket socket) throws IOException {
    output = new PrintWriter(socket.getOutputStream(), true);
    input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
    return this;
  }
  
  /*
    public void send(SocketMessage message) {
      send(message.getRequest());
    }
  */
  
  /**
   * Sends a JSON object.
   * 
   * @param jsonObject the JSON object
   */
  public void send(JSONObject jsonObject) {
    send(jsonObject.toString());
  }
  
  /**
   * Sends a message.
   * 
   * @param message the message
   */
  public synchronized void send(String message) {
    try {
      while(output == null) Thread.sleep(500L);
    } catch(InterruptedException e) { }
    
    synchronized(output) {
      // Logger.info("Sending " + message);
      output.println(message);
    }
  }
  
  private class IncomingDataListener implements Runnable {

    @Override public void run() {
      int datum;
      try {
        while((datum = input.read()) != -1) queue((char)datum);
      } catch(IOException e) { }
    }
    
  }
  
  /*
    public List<Edge> getEdges() {
      return edges;
    }
  */
  
  public UUID getUUID() {
    return uuid;
  }
  
  public Node setUUID(UUID uuid) {
    this.uuid = uuid;
    return this;
  }
  
  public Node setUUID(String uuid) { // TODO might need to add exception handling to this
    return setUUID(UUID.fromString(uuid)); 
  }
  
  public String getInformalName() {
    return informalName;
  }
  
  public Node setInformalName(String informalName) {
    this.informalName = informalName;
    return this;
  }
  
  public boolean equals(Node node) {
    return uuid.compareTo(node.uuid) == 0;
  }
  
  public String getIP() {
    return ip;
  }
  
  public Node setIP(String ip) {
    this.ip = ip;
    return this;
  }
  
  public int getPort() {
    return port;
  }
  
  public Node setPort(int port) {
    this.port = port;
    return this;
  }
  
  public void linkThread(Thread thread) {
    myThread = thread;
  }
  
  public void kill() {
    if(myThread != null) myThread.interrupt();
  }
  
}
