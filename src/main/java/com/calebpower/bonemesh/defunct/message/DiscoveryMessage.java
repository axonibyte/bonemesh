package com.calebpower.bonemesh.defunct.message;

import java.util.Collection;

import org.json.JSONArray;
import org.json.JSONObject;

import com.calebpower.bonemesh.defunct.server.ServerNode;

/**
 * A discovery message to share a list of known nodes.
 * 
 * @author Caleb L. Power
 */
public class DiscoveryMessage extends Message {
  
  /**
   * Overloaded constructor for the discovery message.
   * 
   * @param sendingNode the node of origination
   * @param knownNodes a collection containing all known nodes
   */
  public DiscoveryMessage(ServerNode sendingNode, Collection<ServerNode> knownNodes) {
    super(sendingNode.getName(), Action.DISCOVER, null);
    JSONArray nodeArray = new JSONArray();
    addServerNode(nodeArray, sendingNode);
    addServerNode(nodeArray, knownNodes.toArray());
    put("payload", new JSONObject()
        .put("nodes", nodeArray));
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
