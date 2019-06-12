package com.calebpower.bonemesh.defunct.tx;

import java.util.UUID;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.calebpower.bonemesh.defunct.BoneMesh;
import com.calebpower.bonemesh.defunct.exception.BadTxException;
import com.calebpower.bonemesh.defunct.node.Edge;
import com.calebpower.bonemesh.defunct.node.Node;
import com.calebpower.bonemesh.defunct.node.NodeMap;
import com.calebpower.bonemesh.defunct.socket.IncomingDataHandler;

public class MapTx extends GenericTx {
  
  private NodeMap nodeMap = null;
  
  public MapTx(UUID thisNode, UUID targetNode, NodeMap nodeMap) {
    super(thisNode, targetNode, TxType.MAP_TX);
    System.out.println("NodeMap is " + (nodeMap == null ? "still null." : "not null."));
    this.nodeMap = new NodeMap().sync(nodeMap);
    JSONArray map = new JSONArray();
    for(Node node : this.nodeMap.getNodes()) {
      JSONArray edgeArray = new JSONArray();
      for(Edge edge : this.nodeMap.getEdges(node)) {
        edgeArray.put(new JSONObject()
            .put("uuid", edge.getUUID().toString())
            .put("name", edge.getInformalName())
            .put("weight", edge.getWeight()));
      }
      map.put(new JSONObject()
          .put("uuid", node.getUUID())
          .put("name", node.getInformalName())
          .put("edges", edgeArray));
    }
    getJSONObject("data").put("map", map);
    System.out.println("------------------ MAP ------------------\n"
        + toString(2) + "-----------------------------------------");
  }
  
  public MapTx(JSONObject json) throws BadTxException {
    super(json);
    validateMessageType(TxType.MAP_TX);
    nodeMap = new NodeMap();
    
    try {
      JSONArray map = json.getJSONObject("data").getJSONArray("map");
      System.out.println("------------ GOT MAP OBJECT ------------");
      for(Object nodeObject : map) {
        System.out.println("------------ GOT MAP ---------------");
        JSONObject node = (JSONObject)nodeObject;
        String nodeUUID = node.getString("uuid");
        String nodeName = node.has("name") ? node.getString("name") : null;
        JSONArray edges = node.getJSONArray("edges");
        Node importedNode = new Node().setUUID(nodeUUID).setInformalName(nodeName);
        for(Object edgeObject : edges) {
          System.out.println("----------------- GOT EDGE ------------");
          JSONObject edge = (JSONObject)edgeObject;
          String edgeUUID = edge.getString("uuid");
          String edgeName = edge.has("name") ? edge.getString("name") : edgeUUID;
          long weight = edge.getLong("weight");
          Edge importedEdge = new Edge(importedNode)
              .setUUID(edgeUUID)
              .setInformalName(edgeName)
              .setWeight(weight);
          System.out.println("UPDATING NODE " + importedNode.getUUID() + " -> " + importedEdge.getUUID());
          nodeMap.update(importedNode, importedEdge);
        }
      }
    } catch(JSONException e) {
      throw new BadTxException(e.getMessage());
    }
  }
  
  public synchronized NodeMap getMap() {
    synchronized(nodeMap) {
      while(nodeMap.isUnlocked()) {
        try {
          nodeMap.wait();
        } catch(InterruptedException e) {
          e.printStackTrace();
        }
      }
      return nodeMap;
    }
  }
  
  @Override public void followUp(BoneMesh boneMesh, IncomingDataHandler incomingDataHandler) {
    linkNode(boneMesh, incomingDataHandler);
    if(!route(boneMesh, incomingDataHandler)) {
      boneMesh.getNodeMap().sync(nodeMap);
    }
  }

}
