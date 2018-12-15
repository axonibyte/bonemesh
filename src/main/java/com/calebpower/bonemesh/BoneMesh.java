package com.calebpower.bonemesh;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import com.calebpower.bonemesh.node.Node;
import com.calebpower.bonemesh.node.NodeMap;
import com.calebpower.bonemesh.socket.SocketClient;

/**
 * Virtual Mesh Network for Java.
 * 
 * @author Caleb L. Power
 */
public class BoneMesh {
  
  ExecutorService executor = null;
  private List<Node> nodeList = null; // directly connected nodes
  private NodeMap nodeMap = null; // all known nodes and their known edges
  private String identifier = null;
  private UUID uuid = null;
  
  public BoneMesh() {
    this(null);
  }
  
  public BoneMesh(String identifier) {
    this.nodeList = new CopyOnWriteArrayList<>();
    uuid = UUID.randomUUID();
    if(this.identifier == null)
      this.identifier = uuid.toString();
    else this.identifier = identifier;
    this.executor = Executors.newSingleThreadExecutor();
  }
  
  public BoneMesh connect(String ip, int port) {
    Future<Node> nodePromise = executor.submit(new SocketClient(ip, port));
    try {
      Node node = nodePromise.get();
      if(node != null)
        syncNode(nodeList, node);
    } catch(Exception e) {
      e.printStackTrace();
    }
    return this;
  }
  
  public static void syncNode(List<Node> nodeList, Node node) {
    /*
     * TODO:
     * 1. Iterate through current list of nodes. Search for UUID match.
     * 2. If found, check if there's an existing connection. If so, keep it, kill the new node.
     * 3. If found and there's not an existing connection, sync the IP address (if it has one) and connection.
     * 4. If node is not found, add it to the list.
     */
    synchronized(nodeList) {
      Node found = null;
      for(Node n : nodeList)
        if(node.equals(n)) {
          found = n;
          break;
        }
      if(found == null && node.getIP() != null) {
        for(Node n : nodeList)
          if(node.getIP() == n.getIP() && node.getPort() == n.getPort()) {
            found = n;
            break;
          }
      }
      if(found == null) { // if we didn't find a node, add it
        nodeList.add(node);
        Thread thread = new Thread(node);
        thread.setDaemon(true);
        thread.start();
      } else { // make sure to ensure that old (live) connections are favored
        if(!node.equals(found)) { // the UUIDs are the same, only update informalName
          
        }
      }
      
    }
  }
  
}
