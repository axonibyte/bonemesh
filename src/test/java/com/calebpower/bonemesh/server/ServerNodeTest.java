package com.calebpower.bonemesh.server;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

import com.calebpower.bonemesh.server.ServerNode.SubnetPreference;

public class ServerNodeTest {
  
  private ServerNode serverNode = null;
  
  @Before public void setupServerNode() {
    serverNode = new ServerNode(
        "NAME",
        "EXTERNAL_HOST",
        "INTERNAL_HOST",
        2319,
        false);
  }
  
  @Test public void testIsAlive() {
    assertEquals(false, serverNode.isAlive());
  }
  
  @Test public void testSetAlive() {
    serverNode.setAlive(true);
    assertEquals(true, serverNode.isAlive());
  }
  
  @Test public void testIsEavesdroppingEnabled() {
    assertEquals(false, serverNode.isEavesdroppingEnabled());
  }
  
  @Test public void testGetName() {
    assertEquals("NAME", serverNode.getName());
  }
  
  @Test public void testGetExternalHost() {
    assertEquals("EXTERNAL_HOST", serverNode.getExternalHost());
  }
  
  @Test public void testGetInternalHost() {
    assertEquals("INTERNAL_HOST", serverNode.getInternalHost());
  }
  
  @Test public void testGetPort() {
    assertEquals(2319, serverNode.getPort());
  }
  
  @Test public void testGetSubnetPreference() {
    assertEquals(SubnetPreference.UNKNOWN, serverNode.getSubnetPreference());
  }
  
  @Test public void testSetSubnetPreference() {
    serverNode.setSubnetPreference(SubnetPreference.EXTERNAL);
    assertEquals(SubnetPreference.EXTERNAL, serverNode.getSubnetPreference());
    serverNode.setSubnetPreference(SubnetPreference.INTERNAL);
    assertEquals(SubnetPreference.INTERNAL, serverNode.getSubnetPreference());
  }
}
