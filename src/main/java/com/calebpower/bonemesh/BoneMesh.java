package com.calebpower.bonemesh;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.calebpower.bonemesh.exception.BoneMeshInitializationException;
import com.calebpower.bonemesh.listener.BoneMeshDataListener;
import com.calebpower.bonemesh.listener.BoneMeshInfoListener;
import com.calebpower.bonemesh.message.DeathNote;
import com.calebpower.bonemesh.message.InitRequest;
import com.calebpower.bonemesh.server.NodeWatcher;
import com.calebpower.bonemesh.server.PayloadDispatcher;
import com.calebpower.bonemesh.server.ServerNode;
import com.calebpower.bonemesh.server.SocketListener;

public class BoneMesh {
  
  private Map<String, BoneMeshDataListener> dataListeners = null;
  private Map<String, ServerNode> serverNodes = null;
  private ServerNode thisServer = null;
  private Set<BoneMeshInfoListener> infoListeners = null;
  private SocketListener socketListener = null;
  private Thread socketListenerThread = null;
  private Thread nodeWatcherThread = null;
  
  private BoneMesh(String name) throws BoneMeshInitializationException {
    this.dataListeners = new ConcurrentHashMap<>();
    this.infoListeners = new HashSet<>();
    this.serverNodes = new ConcurrentHashMap<>();
    log("Loading BoneMeshServer " + name + "...");
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
      
      String externalIP = null;
      String internalIP = null;
      
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
      
      boneMesh.thisServer = new ServerNode(boneMesh, name, externalIP, internalIP, 0, false, false);
      
      if(hostPort > 0) boneMesh.thisServer.setMaster(true);
      boneMesh.socketListener = new SocketListener(boneMesh, hostPort);
      boneMesh.socketListenerThread = new Thread(boneMesh.socketListener);
      boneMesh.socketListenerThread.start();
      boneMesh.thisServer.setPort(boneMesh.socketListener.getPort());
      
      if(targetIP != null) {
        if(targetPort < 1 || targetPort > 65535)
          throw new BoneMeshInitializationException(
              BoneMeshInitializationException.ExceptionType.BAD_TARGET_PORT);
        else {
          ServerNode serverNode = new ServerNode(boneMesh, null, targetIP, targetIP, targetPort, false, false);
          boneMesh.dispatch(new InitRequest(boneMesh.thisServer), serverNode);
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

  public void registerDataListener(BoneMeshDataListener listener, String name) {
    if(dataListeners.containsValue(listener))
      deregisterDataListener(listener);
    if(dataListeners.containsKey(name))
      deregisterDataListener(name);
    dataListeners.put(name, listener);
  }
  
  public void deregisterDataListener(String name) {
    if(dataListeners.containsKey(name))
      dataListeners.remove(name);
  }
  
  public void deregisterDataListener(BoneMeshDataListener listener) {
    List<String> keys = new ArrayList<>();
    for(String listenerKey : dataListeners.keySet())
      if(dataListeners.get(listenerKey).equals(listener))
        keys.add(listenerKey);
    
    for(String key : keys)
      dataListeners.remove(key);
  }
  
  public void registerInfoListener(BoneMeshInfoListener listener) {
    if(infoListeners.contains(listener))
      deregisterInfoListener(listener);
    infoListeners.add(listener);
  }
  
  public void deregisterInfoListener(BoneMeshInfoListener listener) {
    infoListeners.remove(listener);
  }
  
  public void log(String message) {
    for(BoneMeshInfoListener listener : infoListeners)
      listener.logBoneMeshInfo(message);
  }
  
  public Map<String, BoneMeshDataListener> getListeners() {
    return dataListeners;
  }
  
  public Collection<ServerNode> getKnownNodes() {
    return serverNodes.values();
  }
  
  public Map<String, Boolean> getNodeList() {
    Map<String, Boolean> nodeList = new HashMap<>();
    for(String key : serverNodes.keySet())
      nodeList.put(key, serverNodes.get(key).isAlive());
    return nodeList;
  }
  
  /*
  public JSONObject generateInitRequest() {
    JSONArray serverList = new JSONArray();
    for(String node : serverNodes.keySet()) {
      ServerNode serverNode = serverNodes.get(node);
      serverList.put(new JSONObject()
          .put("name", node)
          .put("alive", serverNode.isAlive())
          .put("externalHost", serverNode.getExternalHost())
          .put("internalHost", serverNode.getInternalHost())
          .put("port", serverNode.getPort())
          .put("master", serverNode.isMaster()));
    }
    
    serverList.put(new JSONObject()
        .put("name", thisServer.getName())
        .put("alive", true)
        .put("externalHost", thisServer.getExternalHost())
        .put("internalHost", thisServer.getInternalHost())
        .put("port", thisServer.getPort())
        .put("master", thisServer.isMaster()));
    
    return new JSONObject()
        .put("bonemesh", new JSONObject()
            .put("action", "init")
            .put("nodes", serverList));
  }
  */
  
  public void loadNode(String name, JSONObject node) {
    if(name == null) return;
    if(serverNodes.containsKey(name))
      serverNodes.remove(name);
    ServerNode serverNode = new ServerNode(
        this,
        name,
        node.getString("externalHost"),
        node.getString("internalHost"),
        node.getInt("port"),
        false,
        false);
    serverNodes.put(name,  serverNode);
  }
  
  public void loadNodes(JSONArray nodes) {
    try {
      for(Object object : nodes) {
        try {
          JSONObject node = (JSONObject)object;
          String name = node.getString("name");
          if(name == null || serverNodes.containsKey(name) || thisServer.getName().equals(name)) continue;
          ServerNode serverNode = new ServerNode(
              this,
              name,
              node.getString("externalHost"),
              node.getString("internalHost"),
              node.getInt("port"),
              false,
              node.getBoolean("master"));
          //serverNode.setAlive(node.getBoolean("alive"));
          serverNodes.put(name, serverNode);
          dispatch(new InitRequest(thisServer), serverNode);
        } catch(ClassCastException e1) {
          continue;
        }
      }
    } catch(JSONException e2) {
      e2.printStackTrace();
    }
    
    log("I am " + thisServer.getName());
    log("Known servers:");
    Map<String, Boolean> nodeList = getNodeList();
    for(String node : getNodeList().keySet())
      log(node + " (" + (nodeList.get(node) ? "ALIVE" : "DEAD") + ")");
  }
  
  public void unload(String node) {
    log("Unloading " + node + "...");
    serverNodes.remove(node);
  }

  public void disconnect() {
    /*
    dispatch(new JSONObject()
        .put("bonemesh", new JSONObject()
            .put("action", "die")
            .put("node", thisServer.getName())));
            */
    dispatch(new DeathNote(thisServer));
    serverNodes.clear();
  }
  
  public void dispatch(JSONObject payload) {
    for(ServerNode serverNode : serverNodes.values()) {
      Thread thread = new Thread(new PayloadDispatcher(this, serverNode, injectBonemeshObject(payload)));
      thread.setDaemon(true);
      thread.start();
    }
  }
  
  public void dispatch(JSONObject payload, ServerNode serverNode) {
    Thread thread = new Thread(new PayloadDispatcher(this, serverNode, injectBonemeshObject(payload)));
    thread.setDaemon(true);
    thread.start();
  }
  
  public boolean dispatch(JSONObject payload, String node) {
    if(!serverNodes.containsKey(node)) return false;
    Thread thread = new Thread(new PayloadDispatcher(this, serverNodes.get(node), injectBonemeshObject(payload)));
    thread.setDaemon(true);
    thread.start();
    return true;
  }
  
  private JSONObject injectBonemeshObject(JSONObject json) {
    if(!json.has("bonemesh")) {
      json.put("bonemesh", new JSONObject()
          .put("action", "transmit")
          .put("node", thisServer.getName()));
    }
    return json;
  }
  
  public ServerNode getNode(String name) {
    return serverNodes.get(name);
  }
  
  public ServerNode getNode(String host, int port) {
    for(ServerNode serverNode : serverNodes.values())
      if(serverNode.getPort() == port
          && (host.equalsIgnoreCase("127.0.0.1")
              || serverNode.getExternalHost().equalsIgnoreCase(host)
              || serverNode.getInternalHost().equalsIgnoreCase(host)))
        return serverNode;
    return null;
  }
  
  public ServerNode getThisServer() {
    return thisServer;
  }
  
}
