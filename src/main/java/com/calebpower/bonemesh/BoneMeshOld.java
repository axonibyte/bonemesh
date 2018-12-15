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
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.calebpower.bonemesh.exception.BoneMeshInitializationException;
import com.calebpower.bonemesh.listener.BoneMeshDataListener;
import com.calebpower.bonemesh.listener.BoneMeshInfoListener;
import com.calebpower.bonemesh.message.DeathNote;
import com.calebpower.bonemesh.message.DiscoveryMessage;
import com.calebpower.bonemesh.message.InitRequest;
import com.calebpower.bonemesh.message.TransmitRequest;
import com.calebpower.bonemesh.server.NodeWatcher;
import com.calebpower.bonemesh.server.PayloadDispatcher;
import com.calebpower.bonemesh.server.ServerNode;
import com.calebpower.bonemesh.server.SocketListener;

/**
 * Virtual Mesh Network for Java.
 * 
 * @author Caleb L. Power
 */
public class BoneMeshOld {
  
  private Map<String, ServerNode> serverNodes = null;
  private ServerNode thisServer = null;
  private Set<BoneMeshDataListener> dataListeners = null;
  private Set<BoneMeshInfoListener> infoListeners = null;
  private SocketListener socketListener = null;
  private Thread socketListenerThread = null;
  private Thread nodeWatcherThread = null;
  private String[] masterIPs = null;
  private int[] masterPorts = null;
  
  private BoneMeshOld(String name, String[] masterIPs, int[] masterPorts) throws BoneMeshInitializationException {
    this.dataListeners = new CopyOnWriteArraySet<>();
    this.infoListeners = new CopyOnWriteArraySet<>();
    this.serverNodes = new ConcurrentHashMap<>();
    this.masterIPs = masterIPs;
    this.masterPorts = masterPorts;
    log("Loading BoneMeshServer " + name + "...");
  }
  
  /**
   * Creates a new BoneMeshOld instance.
   * 
   * @param name the name of the server
   * @param targetIPs the IP addresses to attempt to connect to
   * @param targetPorts the ports to attempt to connect to
   * @param hostPort the listening port of this server
   * @return BoneMeshOld a new BoneMeshOld instance
   */
  public static BoneMeshOld newInstance(String name, String[] targetIPs, int[] targetPorts, int hostPort) {
    
    try {
      
      {
      
        boolean badArgs = false;
        
        if((hostPort < 1 || hostPort > 65535)
            && (targetIPs == null
                || targetPorts == null
                || targetIPs.length == 0
                || targetPorts.length == 0
                || targetIPs.length != targetPorts.length)) {
          for(int targetPort : targetPorts)
            if(targetPort < 1 || targetPort > 65535) {
              badArgs = true;
              break;
            }
          if(badArgs)
            throw new BoneMeshInitializationException(
                BoneMeshInitializationException.ExceptionType.BAD_INIT_ARGS);
        }
        
        if(!badArgs && hostPort < 0) {
          throw new BoneMeshInitializationException(
              BoneMeshInitializationException.ExceptionType.BAD_HOST_PORT);          
        }
      
      }
        
      BoneMeshOld boneMesh = new BoneMeshOld(name, targetIPs, targetPorts);
      
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
      
      boneMesh.thisServer = new ServerNode(boneMesh, name, externalIP, internalIP, 0, false);
      
      if(hostPort > 0) boneMesh.thisServer.setMaster(true);
      boneMesh.socketListener = new SocketListener(boneMesh, hostPort);
      boneMesh.socketListenerThread = new Thread(boneMesh.socketListener);
      boneMesh.socketListenerThread.start();
      boneMesh.thisServer.setPort(boneMesh.socketListener.getPort());
      
      if(targetIPs != null) {
        List<ServerNode> serverNodes = new LinkedList<>();
        for(int i = 0; i < targetIPs.length; i++) {
          if(targetPorts[i] < 1 || targetPorts[i] > 65535)
            throw new BoneMeshInitializationException(
                BoneMeshInitializationException.ExceptionType.BAD_TARGET_PORT);
          else serverNodes.add(
              new ServerNode(
                  boneMesh,
                  null,
                  targetIPs[i],
                  targetIPs[i],
                  targetPorts[i],
                  false));
        }
        for(int i = 0; i < serverNodes.size(); i++) {
          ServerNode serverNode = new ServerNode(boneMesh, null, targetIPs[i], targetIPs[i], targetPorts[i], false);
          boneMesh.dispatch(new InitRequest(boneMesh.thisServer), serverNodes.get(i));
          boneMesh.dispatch(new DiscoveryMessage(boneMesh.getThisServer(), serverNodes), serverNodes.get(i));
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
  
  /**
   * Creates a new BoneMeshOld instance.
   * 
   * @param name the name of this BoneMeshOld instance
   * @param targetIP a single IP address to connect to
   * @param targetPort a target port to connect to
   * @param hostPort the listening port for this server
   * @return BoneMeshOld a new BoneMeshOld instance
   */
  public static BoneMeshOld newInstance(String name, String targetIP, int targetPort, int hostPort) {
    String[] targetIPs = new String[] { targetIP };
    int[] targetPorts = new int[] { targetPort };
    return newInstance(name, targetIPs, targetPorts, hostPort);
  }
  
  /**
   * Creates a new BoneMeshOld instance.
   * 
   * @param name the name of this BoneMeshOld instance
   * @param targetIPs a sequential list of IP addresses to connect to
   * @param targetPorts a sequential list of port numbers to connect to
   * @return BoneMeshOld a new BoneMeshOld instance
   */
  public static BoneMeshOld newInstance(String name, String[] targetIPs, int[] targetPorts) {
    return newInstance(name, targetIPs, targetPorts, 0);
  }
  
  /**
   * Creates a new BoneMeshOld instance.
   * 
   * @param name the name of this BoneMeshOld instance
   * @param targetIP an IP address to connect to
   * @param targetPort a port to connect to
   * @return BoneMeshOld a new BoneMeshOld instance
   */
  public static BoneMeshOld newInstance(String name, String targetIP, int targetPort) {
    String[] targetIPs = new String[] { targetIP };
    int[] targetPorts = new int[] { targetPort } ;
    return newInstance(name, targetIPs, targetPorts);
  }
  
  /**
   * Creates a new BoneMeshOld instance
   * 
   * @param name the name of this BoneMeshOld server
   * @param hostPort the listening port for this BoneMeshOld server
   * @return BoneMeshOld a new BoneMeshOld instance
   */
  public static BoneMeshOld newInstance(String name, int hostPort) {
    return newInstance(name, new String[] { }, new int[] { }, hostPort);
  }
  
  /**
   * Registers a data listener for incoming messages.
   * 
   * @param listener the data listener
   */
  public void registerDataListener(BoneMeshDataListener listener) {
    if(dataListeners.contains(listener))
      deregisterDataListener(listener);
    dataListeners.add(listener);
  }
  
  /**
   * Deregisters a particular data listener.
   * 
   * @param listener the listener that should be deregistered
   */
  public void deregisterDataListener(BoneMeshDataListener listener) {
    if(dataListeners.contains(listener))
      dataListeners.remove(listener);
  }
  
  /**
   * Registers an information listener for logging.
   * 
   * @param listener the listener that should be registered
   */
  public void registerInfoListener(BoneMeshInfoListener listener) {
    if(infoListeners.contains(listener))
      deregisterInfoListener(listener);
    infoListeners.add(listener);
  }
  
  /**
   * Deregisters an information listener that was used for logging.
   * 
   * @param listener the listener that should be deregistered
   */
  public void deregisterInfoListener(BoneMeshInfoListener listener) {
    infoListeners.remove(listener);
  }
  
  /**
   * Logs a message to the various information listeners.
   * 
   * @param message the message to be logged
   */
  public void log(String message) {
    for(BoneMeshInfoListener listener : infoListeners)
      listener.logBoneMeshInfo(message);
  }
  
  /**
   * Retrieves a map of data listeners.
   * 
   * @return Set containing all known data listeners.
   */
  public Set<BoneMeshDataListener> getDataListeners() {
    return dataListeners;
  }
  
  /**
   * Retrieves a collection of all known server nodes.
   * 
   * @return Collection containing all known server nodes
   */
  public Collection<ServerNode> getKnownNodes() {
    return serverNodes.values();
  }
  
  /**
   * Retrieves a map of nodes, organized by name.
   * 
   * @return Map containing all known server nodes and their names
   */
  public Map<String, Boolean> getNodeList() {
    Map<String, Boolean> nodeList = new HashMap<>();
    for(String key : serverNodes.keySet())
      nodeList.put(key, serverNodes.get(key).isAlive());
    return nodeList;
  }
  
  /**
   * Loads a node.
   * 
   * @param name the name of the node
   * @param node JSON object containing node metadata
   */
  public void loadNode(String name, JSONObject node) {
    if(name == null || thisServer.getName().equals(name)) return;
    if(serverNodes.containsKey(name))
      serverNodes.remove(name);
    ServerNode serverNode = new ServerNode(
        this,
        name,
        node.getString("externalHost"),
        node.getString("internalHost"),
        node.getInt("port"),
        false);
    serverNodes.put(name,  serverNode);
  }
  
  /**
   * Load several nodes at once.
   * 
   * @param nodes JSON array containing node metadata
   */
  public void loadNodes(JSONArray nodes) {
    try {
      for(Object object : nodes) {
        try {
          JSONObject node = (JSONObject)object;
          String name = node.has("name") ? node.getString("name") : null;

          ServerNode serverNode = new ServerNode(
              this,
              name,
              node.getString("externalHost"),
              node.getString("internalHost"),
              node.getInt("port"),
              false);
          
          if(name == null || (name != null
              && !serverNodes.containsKey(name)
              && !thisServer.getName().equals(name))) {
            if(name != null) serverNodes.put(name, serverNode);
            dispatch(new InitRequest(thisServer), serverNode);
          }
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
  
  /**
   * Checks to see if a server node is loaded.
   * 
   * @param node the server node that is to be verified
   * @return <code>true</code> if the node is loaded or
   *         <code>false</code> if the node is not loaded
   */
  public boolean isLoaded(ServerNode node) {
    return serverNodes.containsValue(node);
  }
  
  /**
   * Checks to see if a particular IP/port combination is a master node.
   * Also checks the local host.
   * 
   * @param externalIP the external IP to check
   * @param internalIp the internal IP to check
   * @param port the port number to check
   * @return <code>true</code> if the server is a master node or
   *         <code>false</code> if the server is not a master node
   */
  public boolean isMaster(String externalIP, String internalIp, int port) {
    for(int i = 0; i < masterIPs.length; i++) {
      if(masterPorts[i] == port
          && (masterIPs[i].equals("127.0.0.1")
              || masterIPs[i].equals(externalIP)
              || masterIPs[i].equals(internalIp)))
        return true;
    }
    return false;
  }
  
  /**
   * Unloads a node.
   * 
   * @param node the name of the node to be unloaded
   */
  public void unload(String node) {
    log("Unloading " + node + "...");
    serverNodes.remove(node);
  }

  /**
   * Disconnects this server from the network. 
   */
  public void disconnect() {
    dispatchToAll(new DeathNote(thisServer));
    serverNodes.clear();
  }
  
  /**
   * Dispatches some payload to all known servers.
   * 
   * @param payload the payload to be dispatched
   * @param listenerID a data listener's ID
   */
  public void dispatchToAll(JSONObject payload, String listenerID) {
    for(ServerNode serverNode : serverNodes.values())
      dispatch(payload, serverNode, listenerID);
  }
  
  /**
   * Dispatches some payload to a particular server.
   * 
   * @param payload the payload to be dispatched
   * @param serverNode the target server node
   * @param listenerID a data listener's ID
   */
  public void dispatch(JSONObject payload, ServerNode serverNode, String listenerID) {
    if(!payload.has("bonemesh"))
      payload = new TransmitRequest(thisServer, payload, listenerID);
    
    Thread thread = new Thread(new PayloadDispatcher(this, serverNode, payload));
    thread.setDaemon(true);
    thread.start();
  }
  
  /**
   * Dispatches some payload to a particular server.
   * 
   * @param payload the payload to be dispatched
   * @param node the name of the target server node
   * @param listenerID a data listener's ID
   * @return <code>true</code> if the server is known or
   *         <code>false</code> if the server is unknown
   */
  public boolean dispatch(JSONObject payload, String node, String listenerID) {
    if(!serverNodes.containsKey(node)) return false;
    dispatch(payload, serverNodes.get(node), listenerID);
    return true;
  }
  
  /**
   * Dispatches some payload to all known servers.
   * 
   * @param payload the payload to be dispatched
   */
  public void dispatchToAll(JSONObject payload) {
    for(ServerNode serverNode : serverNodes.values())
      dispatch(payload, serverNode, null);
  }
  
  /**
   * Dispatches some payload to a particular server.
   * 
   * @param payload the payload to be dispatched
   * @param serverNode the target server node
   */
  public void dispatch(JSONObject payload, ServerNode serverNode) {
    if(!payload.has("bonemesh"))
      payload = new TransmitRequest(thisServer, payload, null);
    
    Thread thread = new Thread(new PayloadDispatcher(this, serverNode, payload));
    thread.setDaemon(true);
    thread.start();
  }
  
  /**
   * Dispatches some payload to a particular server.
   * 
   * @param payload the payload to be dispatched
   * @param node the name of the target server node
   * @return <code>true</code> if the server is known or
   *         <code>false</code> if the server is unknown
   */
  public boolean dispatch(JSONObject payload, String node) {
    return dispatch(payload, node, null);
  }
  
  /**
   * Retrieves a server node by name.
   * 
   * @param name the name of the server to be retrieved
   * @return ServerNode if it exists or <code>null</code> if it does not exist
   */
  public ServerNode getNode(String name) {
    return serverNodes.get(name);
  }
  
  /**
   * Retrieves a server node by host and ip) {
   * 
   * @param host the node's IP address
   * @param port the node's listening port
   * @return ServerNode the node if it exists or <code>null</code> if it doesn't
   */
  public ServerNode getNode(String host, int port) {
    for(ServerNode serverNode : serverNodes.values())
      if(serverNode.getPort() == port
          && (host.equalsIgnoreCase("127.0.0.1")
              || serverNode.getExternalHost().equalsIgnoreCase(host)
              || serverNode.getInternalHost().equalsIgnoreCase(host)))
        return serverNode;
    return null;
  }
  
  /**
   * Retrieves this BoneMeshOld server.
   * 
   * @return ServerNode this server node
   */
  public ServerNode getThisServer() {
    return thisServer;
  }
  
}
