package com.calebpower.bonemesh.message;

import java.util.Collection;

import org.json.JSONArray;
import org.json.JSONObject;

import com.calebpower.bonemesh.server.ServerNode;

public class DiscoveryMessage extends Message {
  
  public DiscoveryMessage(ServerNode sendingNode, Collection<ServerNode> knownNodes) {
    super(sendingNode.getName(), Action.DISCOVER, null);
    JSONArray nodeArray = new JSONArray();
    addServerNode(nodeArray, sendingNode);
    addServerNode(nodeArray, knownNodes.toArray());
  }
  
  private static void addServerNode(JSONArray json, Object... nodes) {
    for(Object nodeObject : nodes) {
      ServerNode node = (ServerNode)nodeObject;
      json.put(new JSONObject()
          .put("name", node.getName())
          .put("externalHost", node.getExternalHost())
          .put("internalHost", node.getInternalHost())
          .put("master", node.isMaster())
          .put("port", node.getPort()));
    }
  }
  
}
