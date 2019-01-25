package com.calebpower.bonemesh.socket;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.List;
import java.util.UUID;

import org.json.JSONException;
import org.json.JSONObject;

import com.calebpower.bonemesh.BoneMesh;
import com.calebpower.bonemesh.tx.AckTx;
import com.calebpower.bonemesh.tx.GenericTx;
import com.calebpower.bonemesh.tx.GenericTx.TxType;
import com.calebpower.bonemesh.tx.MapTx;
import com.calebpower.bonemesh.tx.PingTx;

public class IncomingDataHandler implements Runnable {
  
  private BoneMesh boneMesh = null;
  private BufferedReader input = null;
  private List<Character> incomingData = null;
  private List<Character> dataBuffer = null;
  private int curlyCount = 0;
  private int previousCurlyCount = 0;
  private PrintWriter output = null;
  
  private IncomingDataHandler() { }

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
              
              System.out.println(jsonObject.toString());
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
                  transaction.followUp(boneMesh, this);
                  
                  send(new AckTx(boneMesh.getUUID(), UUID.fromString(
                      transaction
                        .getJSONObject("meta")
                        .getString("originNode"))));
                }
                
              } catch(Exception e) {
                send(new AckTx(boneMesh.getUUID(), null, "Malformed transaction."));
              }
                
            } catch(JSONException e) {
              // Logger.error("Some JSONException was thrown in the peer-to-peer connection handler. " + e.getMessage());
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
    } catch(InterruptedException e) { }
  }
  
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
    incomingDataHandler.output = new PrintWriter(socket.getOutputStream(), true);
    incomingDataHandler.input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
    incomingDataHandler.boneMesh = boneMesh;
    Thread thread = new Thread(incomingDataHandler);
    thread.setDaemon(true);
    thread.start();
    return incomingDataHandler;
  }
  
  private class IncomingDataListener implements Runnable {
    
    @Override public void run() {
      int datum;
      try {
        while((datum = input.read()) != -1) queue((char)datum);
      } catch(IOException e) { }
    }
    
  }
  
}
