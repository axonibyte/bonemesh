package com.calebpower.bonemesh;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import com.calebpower.bonemesh.node.Node;
import com.calebpower.bonemesh.node.NodeMap;
import com.calebpower.bonemesh.socket.SocketClient;
import com.calebpower.bonemesh.socket.SocketServer;

/**
 * Virtual Mesh Network for Java.
 * 
 * @author Caleb L. Power
 */
public class BoneMesh {
  
  ExecutorService executor = null;
  private List<Node> nodeList = null; // directly connected nodes
  private NodeMap nodeMap = null; // all known nodes and their known edges
  private SocketServer server = null;
  private String identifier = null;
  private UUID uuid = null;
  
  public BoneMesh() {
    this(null);
  }
  
  public BoneMesh(String identifier) {
    this.nodeList = new CopyOnWriteArrayList<>();
    uuid = UUID.randomUUID();
    if(identifier == null)
      this.identifier = uuid.toString();
    else this.identifier = identifier;
    System.out.println("Set identifier as " + this.identifier);
    this.executor = Executors.newSingleThreadExecutor();
  }
  
  public static void main(String[] args) throws ParseException { // this is for testing
    Options options = new Options();
    options.addOption("l", "listening_port", true, "Server listening port.");
    options.addOption("t", "target_nodes", true, "Target nodes.");
    options.addOption("n", "informal_name", true, "Informal name.");
    CommandLineParser parser = new DefaultParser();
    CommandLine cmd = parser.parse(options, args);
    
    BoneMesh boneMesh = cmd.hasOption("informal_name")
        ? new BoneMesh(cmd.getOptionValue("informal_name"))
            : new BoneMesh();
    
    if(cmd.hasOption("listening_port")) {
      try {
        int port = Integer.parseInt(cmd.getOptionValue("listening_port"));
        System.out.println("Spinning up server on port " + port);
        boneMesh.spinUp(port);
      } catch(NumberFormatException e){
        System.out.println("Invalid listening port.");
        System.exit(1);
      }
    }
    
    if(cmd.hasOption("target_nodes")) {
      String[] nodes = cmd.getOptionValue("target_nodes").split(",");
      for(String node : nodes) {
        try {
          String[] host = node.split(":");
          int port = Integer.parseInt(host[1]);
          System.out.println("Connecting to " + host[0] + ":" + port);
          boneMesh.connect(host[0], port);
        } catch(Exception e) {
          System.out.println("Exception thrown when parsing for '" + node + "'");
          System.exit(1);
        }
      }
    }
    
    try {
      for(;;)
        Thread.sleep(500L);
    } catch(InterruptedException e) {
      System.out.println("Exiting.");
    }
      
  }
  
  public BoneMesh connect(String ip, int port) {
    SocketClient.build(this, ip, port);
    
    /*
      Future<Node> nodePromise = executor.submit(new SocketClient(ip, port));
      try {
        Node node = nodePromise.get();
        if(node != null)
          syncNode(nodeList, node);
      } catch(Exception e) {
        e.printStackTrace();
      }
    */
    
    return this;
  }
  
  public BoneMesh spinUp(int port) {
    server = new SocketServer(this, port).start();
    return this;
  }
  
  public void syncNode(Node node) {
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
        //node.start();
      } else { // make sure to ensure that old (live) connections are favored
        if(!node.equals(found)) { // the UUIDs are different, so the old connection needs to be discarded
          //found.kill();
          nodeList.remove(found);
          nodeList.add(node);
          //node.start();
        }
      }
      
    }
  }
  
}
