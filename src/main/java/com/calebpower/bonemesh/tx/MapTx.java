package com.calebpower.bonemesh.tx;

import java.util.UUID;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.calebpower.bonemesh.BoneMesh;
import com.calebpower.bonemesh.exception.BadTxException;
import com.calebpower.bonemesh.node.Edge;
import com.calebpower.bonemesh.node.Node;
import com.calebpower.bonemesh.node.NodeMap;

public class MapTx extends GenericTx {
  
  private NodeMap nodeMap = null;
  
  public MapTx(UUID thisNode, UUID targetNode, NodeMap nodeMap) {
    super(thisNode, targetNode, TxType.MAP_TX);
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
  }
  
  public MapTx(JSONObject json) throws BadTxException {
    super(json);
    validateMessageType(TxType.MAP_TX);
    nodeMap = new NodeMap();
    
    try {
      JSONArray map = json.getJSONArray("map");
      for(Object nodeObject : map) {
        JSONObject node = (JSONObject)nodeObject;
        String nodeUUID = node.getString("uuid");
        String nodeName = node.getString("name");
        JSONArray edges = json.getJSONArray("edges");
        Node importedNode = new Node().setUUID(nodeUUID).setInformalName(nodeName);
        for(Object edgeObject : edges) {
          JSONObject edge = (JSONObject)edgeObject;
          String edgeUUID = edge.getString("uuid");
          String edgeName = edge.getString("name");
          long weight = edge.getLong("weight");
          Edge importedEdge = new Edge(importedNode)
              .setUUID(edgeUUID)
              .setInformalName(edgeName)
              .setWeight(weight);
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
        } catch(InterruptedException e) { }
      }
      return nodeMap;
    }
  }
  
  @Override public void execute(BoneMesh boneMesh) {
    // TODO execute map transaction
  }

}
