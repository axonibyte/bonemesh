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
import com.calebpower.bonemesh.server.PayloadDispatcher;
import com.calebpower.bonemesh.server.ServerNode;
import com.calebpower.bonemesh.server.SocketListener;

import listener.JSONListener;

public class BoneMesh {
  
  private Map<String, JSONListener> jsonListeners = null;
  private Map<String, ServerNode> serverNodes = null;
  private SocketListener socketListener = null;
  private String name = null;
  private String externalIP = null;
  private String internalIP = null;
  
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
      
      if(targetIP != null) {
        if(targetPort < 1 || targetPort > 65535)
          throw new BoneMeshInitializationException(
              BoneMeshInitializationException.ExceptionType.BAD_TARGET_PORT);
        else {
          ServerNode serverNode = new ServerNode(null, targetIP, targetIP, targetPort, false);
          boneMesh.dispatch(boneMesh.generateInitRequest(), serverNode);
        }
      }
      
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
          .put("node", node)
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
        .put("bonemesh", "init")
        .put("nodes", serverList);
  }
  
  public void loadNodes(JSONArray nodes) {
    try {
      for(Object object : nodes) {
        try {
          JSONObject node = (JSONObject)object;
          String name = node.getString("name");
          if(serverNodes.containsKey(name)) continue;
          ServerNode serverNode = new ServerNode(
              name,
              node.getString("externalHost"),
              node.getString("internalHost"),
              node.getInt("port"),
              false);
          serverNode.setAlive(node.getBoolean("alive"));
          serverNodes.put(name, serverNode);
        } catch(BoneMeshInitializationException | ClassCastException e1) {
          continue;
        }
      }
    } catch(JSONException e2) { }
  }
  
  public void dispatch(JSONObject payload) {
    for(ServerNode serverNode : serverNodes.values()) {
      Thread thread = new Thread(new PayloadDispatcher(serverNode, payload));
      thread.setDaemon(true);
      thread.start();
    }
  }
  
  public void dispatch(JSONObject payload, ServerNode serverNode) {
    Thread thread = new Thread(new PayloadDispatcher(serverNode, payload));
    thread.setDaemon(true);
    thread.start();
  }
  
  public boolean dispatch(JSONObject payload, String node) {
    if(!serverNodes.containsKey(node)) return false;
    Thread thread = new Thread(new PayloadDispatcher(serverNodes.get(node), payload));
    thread.setDaemon(true);
    thread.start();
    return true;
  }
  
}
