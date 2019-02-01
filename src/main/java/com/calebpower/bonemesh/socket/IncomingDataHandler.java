package com.calebpower.bonemesh.socket;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

import org.json.JSONException;
import org.json.JSONObject;

import com.calebpower.bonemesh.BoneMesh;
import com.calebpower.bonemesh.tx.AckTx;
import com.calebpower.bonemesh.tx.GenericTx;
import com.calebpower.bonemesh.tx.GenericTx.TxType;
import com.calebpower.bonemesh.tx.MapTx;
import com.calebpower.bonemesh.tx.PingTx;

public class IncomingDataHandler implements Runnable {
  
  private AtomicLong lastAck = null;
  private BoneMesh boneMesh = null;
  private BufferedReader input = null;
  //private BufferedWriter output = null;
  private List<Character> incomingData = null;
  private List<Character> dataBuffer = null;
  private int curlyCount = 0;
  private int previousCurlyCount = 0;
  private PrintWriter output = null;
  private Thread thread = null;
  
  private IncomingDataHandler() {
    incomingData = new LinkedList<>();
    dataBuffer = new LinkedList<>();
    lastAck = new AtomicLong(System.currentTimeMillis());
  }

  @Override public void run() {
    new Thread(new IncomingDataListener()).start();
    
    //send(new GenericTx(boneMesh.getUUID(), null, TxType.GENERIC_TX,
        //new JSONObject().put("message", "MSG 0 FROM " + boneMesh.getIdentifier())));
    
    System.out.println("Hit.");
    
    try {
      // Logger.info("Spinning up a message handler.");
      while(!Thread.interrupted()) {
        //send(new GenericTx(boneMesh.getUUID(), null, TxType.GENERIC_TX,
            //new JSONObject().put("message", "MSG 1 FROM " + boneMesh.getIdentifier())));
        
        char current;
        
        synchronized(incomingData) {
          while(incomingData.isEmpty()) {
            incomingData.wait();
          }
          current = incomingData.remove(0);
        }

        //send(new GenericTx(boneMesh.getUUID(), null, TxType.GENERIC_TX,
            //new JSONObject().put("message", "MSG 2 FROM " + boneMesh.getIdentifier())));
        
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
            
            JSONObject jsonObject = null;
            
            try {
              jsonObject = new JSONObject(new String(characters));
              
              System.out.println("I am " + boneMesh.getUUID().toString());
              System.out.println("Received data:");
              System.out.println(jsonObject.toString(2));
              // TODO do something with jsonObject here, including calling BoneMesh.syncNode
              // basically, interpret the JSON object at this point in time.
              
              GenericTx transaction = null;
              
              try {
                TxType txType = TxType.fromString(jsonObject.getJSONObject("meta").getString("messageType"));
                if(txType == null) txType = TxType.GENERIC_TX;
                switch(txType) {
                case ACK_TX:
                  transaction = new AckTx(jsonObject);
                  break;
                case MAP_TX:
                  transaction = new MapTx(jsonObject);
                  break;
                case PING_TX:
                  transaction = new PingTx(jsonObject);
                  break;
                case GENERIC_TX:
                default:
                  transaction = new GenericTx(jsonObject);
                  break;
                }
                
                System.out.println("Received " + txType + " transaction.");
                
                if(!transaction.isOfType(TxType.ACK_TX)) {
                  send(new AckTx(boneMesh.getUUID(), UUID.fromString(
                      transaction
                        .getJSONObject("meta")
                        .getString("originNode")), boneMesh));
                }
                  
                transaction.followUp(boneMesh, this);
                
              } catch(Exception e) {
                e.printStackTrace();
                
                UUID originNode = null;
                try {
                  String uuid = jsonObject
                    .getJSONObject("meta")
                    .getString("originNode");
                  if(uuid != null)
                    originNode = UUID.fromString(uuid);
                } catch(JSONException e2) {
                  e2.printStackTrace();
                }
                
                send(new AckTx(boneMesh.getUUID(), originNode, "Malformed transaction."));
              }
                
            } catch(JSONException e) {
              // Logger.error("Some JSONException was thrown in the peer-to-peer connection handler. " + e.getMessage());
              e.printStackTrace();
              send(new AckTx(boneMesh.getUUID(), null, e.getMessage()));
            }
            
            dataBuffer.clear();
            
          } else { //Some syntax error.
            // Logger.error("Some JSONException was thrown in the peer-to-peer connection handler (mismatched curly braces).");
            System.out.println("Got some syntax error.");
            send(new AckTx(boneMesh.getUUID(), null, "Syntax error: mismatched curly braces."));
            continue;
          }
        }
      }
    } catch(InterruptedException e) {
      e.printStackTrace();
    }
  }
  
  /**
   * Sends a JSON object.
   * 
   * @param jsonObject the JSON object
   */
  public boolean send(JSONObject jsonObject) {
    //System.out.println("Sending message...");
    System.out.println(jsonObject.toString(0));
    return send(jsonObject.toString());
    //System.out.println("Sent!");
  }
  
  /**
   * Sends a message.
   * 
   * @param message the message
   */
  public synchronized boolean send(String message) {
    try {
      while(output == null) Thread.sleep(500L);
    } catch(InterruptedException e) {
      e.printStackTrace();
    }
    
    try {
      synchronized(output) {
        // Logger.info("Sending " + message);
        output.println(message);
        //output.write(message.toCharArray());
        //output.newLine();
        output.flush();
      }
      return true;
    } catch(Exception e) {
      e.printStackTrace();
    }
    return false;
  }
  
  public boolean isStale() {
    return System.currentTimeMillis() - lastAck.get() > 10000L; // ten seconds
  }
  
  public boolean isDead() {
    return System.currentTimeMillis() - lastAck.get() > 20000L; // twenty seconds
  }
  
  public void touch() {
    lastAck.set(System.currentTimeMillis());
  }
  
  public void kill() {
    thread.interrupt();
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
  
  public static IncomingDataHandler build(BoneMesh boneMesh, Socket socket) throws IOException {
    IncomingDataHandler incomingDataHandler = new IncomingDataHandler();
    incomingDataHandler.input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
    incomingDataHandler.output = new PrintWriter(socket.getOutputStream(), true); //new PrintWriter(socket.getOutputStream(), true);
    incomingDataHandler.boneMesh = boneMesh;
    //System.out.println("Builing!");
    //incomingDataHandler.output.println(new GenericTx(boneMesh.getUUID(), null, TxType.GENERIC_TX,
        //new JSONObject().put("message", "MSG C FROM " + boneMesh.getIdentifier())).toString());
    //System.out.println("Built!");
    Thread thread = new Thread(incomingDataHandler);
    incomingDataHandler.thread = thread;
    thread.setDaemon(true);
    thread.start();
    return incomingDataHandler;
  }
  
  private class IncomingDataListener implements Runnable {
    
    @Override public void run() {
      int datum;
      try {
        while((datum = input.read()) != -1) queue((char)datum);
      } catch(IOException e) {
        System.out.println("Could not read from socket: " + e.getMessage());
      }
    }
    
  }
  
}
