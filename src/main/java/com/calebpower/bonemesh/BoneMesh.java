package com.calebpower.bonemesh;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.calebpower.bonemesh.exception.BoneMeshInitializationException;
import com.calebpower.bonemesh.listener.JSONListener;
import com.calebpower.bonemesh.server.NodeWatcher;
import com.calebpower.bonemesh.server.PayloadDispatcher;
import com.calebpower.bonemesh.server.ServerNode;
import com.calebpower.bonemesh.server.SocketListener;

public class BoneMesh {
  
  private Map<String, JSONListener> jsonListeners = null;
  private Map<String, ServerNode> serverNodes = null;
  private SocketListener socketListener = null;
  private String name = null;
  private String externalIP = null;
  private String internalIP = null;
  private Thread socketListenerThread = null;
  private Thread nodeWatcherThread = null;
  
  private BoneMesh(String name) throws BoneMeshInitializationException {
    this.name = name;
    this.jsonListeners = new ConcurrentHashMap<>();
    this.serverNodes = new ConcurrentHashMap<>();
    
    try {
      final URL externalIPService = new URL("http://checkip.amazonaws.com");
      BufferedReader in = new BufferedReader(new InputStreamReader(
          externalIPService.openStream()));
      externalIP = in.readLine();
    } catch(IOException e) { }
    
    try {
      InetAddress thisIp = InetAddress.getLocalHost();
      internalIP = thisIp.getHostAddress().toString();
    } catch (Exception e) { }
  }
  
  public static BoneMesh newInstance(String name, String targetIP, int targetPort, int hostPort) {
    System.out.println("Loading BoneMesh server " + name + "...");
    
    try {
      if(targetIP == null
          && (targetPort < 1 || targetPort > 65535)
          && (hostPort < 1 || hostPort > 65535))
        throw new BoneMeshInitializationException(
            BoneMeshInitializationException.ExceptionType.BAD_INIT_ARGS);
      else if(hostPort < 0)
        throw new BoneMeshInitializationException(
            BoneMeshInitializationException.ExceptionType.BAD_HOST_PORT);
      
      BoneMesh boneMesh = new BoneMesh(name);
      boneMesh.socketListener = new SocketListener(boneMesh, hostPort);
      boneMesh.socketListenerThread = new Thread(boneMesh.socketListener);
      boneMesh.socketListenerThread.start();
      
      if(targetIP != null) {
        if(targetPort < 1 || targetPort > 65535)
          throw new BoneMeshInitializationException(
              BoneMeshInitializationException.ExceptionType.BAD_TARGET_PORT);
        else {
          ServerNode serverNode = new ServerNode(null, targetIP, targetIP, targetPort, false);
          boneMesh.dispatch(boneMesh.generateInitRequest(), serverNode);
        }
      }
      
      boneMesh.nodeWatcherThread = new Thread(new NodeWatcher(boneMesh));
      boneMesh.nodeWatcherThread.setDaemon(true);
      boneMesh.nodeWatcherThread.start();
      
      return boneMesh;
    } catch(BoneMeshInitializationException e) {
      e.printStackTrace();
    }
    
    return null;
  }
  
  public static BoneMesh newInstance(String name, String targetIP, int targetPort) {
    return newInstance(name, targetIP, targetPort, 0);
  }
  
  public static BoneMesh newInstance(String name, int hostPort) {
    return newInstance(name, null, -1, hostPort);
  }
  
  public void registerListener(JSONListener listener, String name) {
    if(jsonListeners.containsValue(listener))
      deregisterListener(listener);
    if(jsonListeners.containsKey(name))
      deregisterListener(name);
    jsonListeners.put(name, listener);
  }
  
  public void deregisterListener(String name) {
    if(jsonListeners.containsKey(name))
      jsonListeners.remove(name);
  }
  
  public void deregisterListener(JSONListener listener) {
    List<String> keys = new ArrayList<>();
    for(String listenerKey : jsonListeners.keySet())
      if(jsonListeners.get(listenerKey).equals(listener))
        keys.add(listenerKey);
    
    for(String key : keys)
      jsonListeners.remove(key);
  }
  
  public Map<String, JSONListener> getListeners() {
    return jsonListeners;
  }
  
  public Map<String, Boolean> getNodeList() {
    Map<String, Boolean> nodeList = new HashMap<>();
    for(String key : serverNodes.keySet())
      nodeList.put(key, serverNodes.get(key).isAlive());
    return nodeList;
  }
  
  public JSONObject generateInitRequest() {
    JSONArray serverList = new JSONArray();
    for(String node : serverNodes.keySet()) {
      ServerNode serverNode = serverNodes.get(node);
      serverList.put(new JSONObject()
          .put("name", node)
          .put("alive", serverNode.isAlive())
          .put("externalHost", serverNode.getExternalHost())
          .put("internalHost", serverNode.getInternalHost())
          .put("port", serverNode.getPort()));
    }
    
    serverList.put(new JSONObject()
        .put("name", name)
        .put("alive", true)
        .put("externalHost", externalIP)
        .put("internalHost", internalIP)
        .put("port", socketListener.getPort()));
    
    return new JSONObject()
        .put("bonemesh", new JSONObject()
            .put("action", "init")
            .put("nodes", serverList));
  }
  
  public void loadNodes(JSONArray nodes) {
    try {
      for(Object object : nodes) {
        try {
          JSONObject node = (JSONObject)object;
          String name = node.getString("name");
          if(serverNodes.containsKey(name) || this.name.equals(name)) continue;
          ServerNode serverNode = new ServerNode(
              name,
              node.getString("externalHost"),
              node.getString("internalHost"),
              node.getInt("port"),
              false);
          serverNode.setAlive(node.getBoolean("alive"));
          serverNodes.put(name, serverNode);
          dispatch(generateInitRequest(), serverNode);
        } catch(ClassCastException e1) {
          continue;
        }
      }
    } catch(JSONException e2) {
      e2.printStackTrace();
    }
    
    System.out.println("I am " + this.name);
    System.out.println("Known servers:");
    Map<String, Boolean> nodeList = getNodeList();
    for(String node : getNodeList().keySet())
      System.out.println(node + " (" + (nodeList.get(node) ? "ALIVE" : "DEAD") + ")");
  }
  
  public void unload(String node) {
    System.out.println("Unloading " + node + "...");
    serverNodes.remove(node);
  }

  public void disconnect() {
    dispatch(new JSONObject()
        .put("bonemesh", new JSONObject()
            .put("action", "die")
            .put("node", name)));
    serverNodes.clear();
  }
  
  public String getName() {
    return name;
  }
  
  public void dispatch(JSONObject payload) {
    for(ServerNode serverNode : serverNodes.values()) {
      Thread thread = new Thread(new PayloadDispatcher(serverNode, injectBonemeshObject(payload)));
      thread.setDaemon(true);
      thread.start();
    }
  }
  
  public void dispatch(JSONObject payload, ServerNode serverNode) {
    Thread thread = new Thread(new PayloadDispatcher(serverNode, injectBonemeshObject(payload)));
    thread.setDaemon(true);
    thread.start();
  }
  
  public boolean dispatch(JSONObject payload, String node) {
    if(!serverNodes.containsKey(node)) return false;
    Thread thread = new Thread(new PayloadDispatcher(serverNodes.get(node), injectBonemeshObject(payload)));
    thread.setDaemon(true);
    thread.start();
    return true;
  }
  
  private JSONObject injectBonemeshObject(JSONObject json) {
    if(!json.has("bonemesh")) {
      json.put("bonemesh", new JSONObject()
          .put("action", "transmit")
          .put("node", name));
    }
    return json;
  }
  
  public ServerNode getNode(String name) {
    return serverNodes.get(name);
  }
  
  public ServerNode getNode(String host, int port) {
    for(ServerNode serverNode : serverNodes.values()) {
      System.out.println("Checking " + host + ":" + port + " against "
          + "127.0.0.1:" + serverNode.getPort() + ", "
          + serverNode.getExternalHost() + ":" + serverNode.getPort() + ", and "
          + serverNode.getInternalHost() + ":" + serverNode.getPort() + ".");
      if(serverNode.getPort() == port
          && (host.equalsIgnoreCase("127.0.0.1")
              || serverNode.getExternalHost().equalsIgnoreCase(host)
              || serverNode.getInternalHost().equalsIgnoreCase(host)))
        return serverNode;
    }
    return null;
  }
  
}
