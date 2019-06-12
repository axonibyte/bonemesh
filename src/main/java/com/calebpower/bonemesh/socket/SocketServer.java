package com.calebpower.bonemesh.socket;

import java.io.IOException;
import java.net.BindException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.json.JSONObject;

import com.calebpower.bonemesh.listener.DataListener;

public class SocketServer implements Runnable {
  
  private int port;
  private List<DataListener> dataListeners = null;
  private List<IncomingSocketHandler> handlers = null;
  private Thread thread = null;
  
  private SocketServer(int port) {
    this.port = port;
    this.dataListeners = new CopyOnWriteArrayList<>();
    this.handlers = new CopyOnWriteArrayList<>();
  }
  
  public static SocketServer build(int port) {
    SocketServer socketServer = new SocketServer(port);
    socketServer.thread = new Thread(socketServer);
    socketServer.thread.setDaemon(true);
    socketServer.thread.start();
    return socketServer;
  }
  
  @Override public void run() {
    while(!thread.isInterrupted()) { // keep the server alive
      try(ServerSocket serverSocket = new ServerSocket(port)) {
        System.out.printf("SERVER OPENED TO PORT %1$d\n", port);
        Socket socket = null;
        serverSocket.setSoTimeout(0);
        while((socket = serverSocket.accept()) != null) {
          System.out.println("SERVER ACCEPTED SOCKET CONNECTION");
          IncomingSocketHandler handler = new IncomingSocketHandler();
          handlers.add(handler);
          handler.handle(socket, this);
        }
      } catch(BindException e) {
        e.printStackTrace();
        throw new RuntimeException(e);
      } catch(IOException e) {
        e.printStackTrace();
      }
    }
  }
  
  public void dispatchToListeners(JSONObject json) {
    for(DataListener listener : dataListeners)
      listener.digest(json); // potentially blocking, TODO fix later
  }

  public void killHandler(IncomingSocketHandler handler) {
    handlers.remove(handler);
  }
  
  public void kill() {
    thread.interrupt();
    for(IncomingSocketHandler handler : handlers)
      handler.kill();
  }
  
  public void addDataListener(DataListener listener) {
    dataListeners.add(listener);
  }
  
  public void removeDataListener(DataListener listener) {
    dataListeners.remove(listener);
  }
}
