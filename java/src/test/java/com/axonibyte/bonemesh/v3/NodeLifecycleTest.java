/*
 * Copyright (c) 2026 Axonibyte Innovations, LLC. All rights reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.axonibyte.bonemesh.v3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import com.axonibyte.bonemesh.v3.cert.Certificate;
import com.axonibyte.bonemesh.v3.message.Messages;
import com.axonibyte.bonemesh.v3.routing.RoutingTable;

/**
 * Link registration lifecycle (protocol.md &sect;3): a stale link's death must
 * never withdraw the live link's routes, and register must record who initiated
 * the connection. The node's link map and PeerLink are internal, so this test
 * reaches them by reflection and drives a real loopback socket pair, which keeps
 * the assertions deterministic (no dependence on the 1&nbsp;s heartbeat, which
 * would otherwise re-seed a wrongly-withdrawn neighbor and mask the bug).
 *
 * @author Caleb L. Power
 */
public final class NodeLifecycleTest {

  // A minimal node with no listening socket bound to any real peers — we only
  // exercise its link map and routing table.
  private static Node bareNode() throws Exception {
    Certificate self = new Certificate("m", "self", new byte[0], 0, 0);
    // Signer is only needed to run a real handshake; these tests never do, so a
    // node started on an ephemeral port with a throwaway identity is enough.
    com.axonibyte.bonemesh.v3.crypto.Signer id = com.axonibyte.bonemesh.v3.crypto.Signer.generate(
        com.axonibyte.bonemesh.v3.crypto.Signer.Level.DSA65, new java.security.SecureRandom());
    return Node.start("self", "m", new byte[0], self, id, 0);
  }

  private static Object peerLink(Node node, String peer, Socket socket, boolean initiator)
      throws Exception {
    Class<?> plClass = Class.forName("com.axonibyte.bonemesh.v3.Node$PeerLink");
    Class<?> tsClass = Class.forName("com.axonibyte.bonemesh.v3.transport.TransportSession");
    Class<?> sessClass = Class.forName("com.axonibyte.bonemesh.v3.handshake.Session");
    Constructor<?> sessCtor =
        sessClass.getDeclaredConstructor(byte[].class, byte[].class, Certificate.class, byte[].class);
    sessCtor.setAccessible(true);
    Object session = sessCtor.newInstance(new byte[32], new byte[32],
        new Certificate("m", peer, new byte[0], 0, 0), new byte[32]);
    Object ts = tsClass.getConstructor(sessClass).newInstance(session);
    // The inner-class constructor takes the enclosing Node as its first arg.
    Constructor<?> plCtor = plClass.getDeclaredConstructor(
        Node.class, String.class, Socket.class, tsClass, boolean.class, String.class);
    plCtor.setAccessible(true);
    return plCtor.newInstance(node, peer, socket, ts, initiator, "0000000000000000");
  }

  private static void registerLink(Node node, String peer, Object link) throws Exception {
    Method m = Node.class.getDeclaredMethod("registerLink", String.class,
        Class.forName("com.axonibyte.bonemesh.v3.Node$PeerLink"));
    m.setAccessible(true);
    m.invoke(node, peer, link);
  }

  private static void closeLink(Object link) throws Exception {
    Method m = link.getClass().getDeclaredMethod("close");
    m.setAccessible(true);
    m.invoke(link);
  }

  private static RoutingTable routing(Node node) throws Exception {
    Field f = Node.class.getDeclaredField("routing");
    f.setAccessible(true);
    return (RoutingTable) f.get(node);
  }

  @Test
  void staleLinkDeathDoesNotWithdrawTheLiveNeighbor() throws Exception {
    Node node = bareNode();
    try(ServerSocket ss = new ServerSocket(0)) {
      // Two connected loopback socket pairs stand in for two competing links.
      Socket c1 = new Socket();
      c1.connect(new InetSocketAddress("127.0.0.1", ss.getLocalPort()));
      Socket s1 = ss.accept();
      Socket c2 = new Socket();
      c2.connect(new InetSocketAddress("127.0.0.1", ss.getLocalPort()));
      Socket s2 = ss.accept();

      Object link1 = peerLink(node, "peer", c1, true);
      Object link2 = peerLink(node, "peer", c2, true);

      registerLink(node, "peer", link1);
      registerLink(node, "peer", link2); // reconnect: displaces and closes link1
      assertTrue(routing(node).isNeighbor("peer"), "live link must be a neighbor after reconnect");

      // link1's reader thread finally notices EOF and calls close() — a stale
      // close arriving after link2 is fully registered. It must NOT withdraw
      // the neighbor that link2 now owns.
      closeLink(link1);
      assertTrue(routing(node).isNeighbor("peer"),
          "stale link death withdrew the live link's neighbor");

      // Control: the CURRENT link's death does withdraw the neighbor — proves
      // the guard discriminates rather than never withdrawing.
      closeLink(link2);
      assertFalse(routing(node).isNeighbor("peer"),
          "current link death failed to withdraw the neighbor");
      s1.close();
      s2.close();
    } finally {
      node.kill();
    }
  }

  @Test
  void registerRecordsInitiatorFlag() throws Exception {
    Node node = bareNode();
    try(ServerSocket ss = new ServerSocket(0)) {
      Socket c = new Socket();
      c.connect(new InetSocketAddress("127.0.0.1", ss.getLocalPort()));
      Socket s = ss.accept();
      Object dialed = peerLink(node, "peer", c, true);
      Field f = dialed.getClass().getDeclaredField("initiator");
      f.setAccessible(true);
      assertTrue((boolean) f.get(dialed), "dialer link must record initiator=true");

      Socket c2 = new Socket();
      c2.connect(new InetSocketAddress("127.0.0.1", ss.getLocalPort()));
      Socket s2 = ss.accept();
      Object accepted = peerLink(node, "peer2", c2, false);
      assertFalse((boolean) f.get(accepted), "accepter link must record initiator=false");
      c.close(); s.close(); c2.close(); s2.close();
    } finally {
      node.kill();
    }
  }

  private static Object linkFor(Node node, String peer) throws Exception {
    Field f = Node.class.getDeclaredField("links");
    f.setAccessible(true);
    @SuppressWarnings("unchecked")
    java.util.Map<String, Object> links = (java.util.Map<String, Object>) f.get(node);
    return links.get(peer.toLowerCase(java.util.Locale.ROOT));
  }

  private static boolean initiatorOf(Object peerLink) throws Exception {
    Field f = peerLink.getClass().getDeclaredField("initiator");
    f.setAccessible(true);
    return (boolean) f.get(peerLink);
  }

  private static void setLong(Object obj, String field, long v) throws Exception {
    Field f = obj.getClass().getDeclaredField(field);
    f.setAccessible(true);
    f.setLong(obj, v);
  }

  private static void sweep(Node node, long now, Object peerLink) throws Exception {
    Method m = Node.class.getDeclaredMethod("sweepLink", long.class,
        Class.forName("com.axonibyte.bonemesh.v3.Node$PeerLink"));
    m.setAccessible(true);
    m.invoke(node, now, peerLink);
  }

  private static Socket[] loopbackPair(ServerSocket ss) throws Exception {
    Socket c = new Socket();
    c.connect(new InetSocketAddress("127.0.0.1", ss.getLocalPort()));
    Socket s = ss.accept();
    return new Socket[] {c, s};
  }

  // F1: on a dial collision both ends keep the session initiated by the
  // lower-labelled node, regardless of registration order. self="self": against
  // a higher peer ("zzz") self keeps its own-initiated link; against a lower
  // peer ("aaa") it keeps the one it accepted.
  @Test
  void tiebreakKeepsLowerLabelInitiatedSession() throws Exception {
    String[] peers = {"zzz", "aaa"};
    boolean[] wants = {true, false}; // self<zzz keep self-initiated; self>aaa keep accepted
    for(int i = 0; i < peers.length; i++) {
      for(boolean firstInitiator : new boolean[] {true, false}) {
        Node node = bareNode();
        try(ServerSocket ss = new ServerSocket(0)) {
          Socket[] p1 = loopbackPair(ss);
          Socket[] p2 = loopbackPair(ss);
          registerLink(node, peers[i], peerLink(node, peers[i], p1[0], firstInitiator));
          registerLink(node, peers[i], peerLink(node, peers[i], p2[0], !firstInitiator));
          Object survivor = linkFor(node, peers[i]);
          assertTrue(survivor != null, "no surviving link");
          assertEquals(wants[i], initiatorOf(survivor),
              "peer=" + peers[i] + " firstInitiator=" + firstInitiator + ": wrong session survived");
          for(Socket s : new Socket[] {p1[0], p1[1], p2[0], p2[1]}) s.close();
        } finally {
          node.kill();
        }
      }
    }
  }

  // F3: a link silent past the probe timeout is torn down and its routes
  // withdrawn; a fresh link is kept.
  @Test
  void probeTimeoutClosesSilentLink() throws Exception {
    Node node = bareNode();
    node.useTunablesForTest(Tunables.forTest(100L, 0L));
    try(ServerSocket ss = new ServerSocket(0)) {
      Socket[] p = loopbackPair(ss);
      Object link = peerLink(node, "peer", p[0], true);
      registerLink(node, "peer", link);

      long now = System.currentTimeMillis();
      sweep(node, now, link); // fresh: kept
      assertTrue(routing(node).isNeighbor("peer"), "a fresh link was wrongly torn down");

      setLong(link, "lastInboundMillis", now - 5000); // silent past the 100ms timeout
      sweep(node, now, link);
      assertFalse(routing(node).isNeighbor("peer"), "probe-timed-out link not torn down");
      assertTrue(linkFor(node, "peer") == null, "dead link not removed from the map");
      for(Socket s : p) s.close();
    } finally {
      node.kill();
    }
  }

  // F4: with idle teardown enabled a link carrying no data past the idle timeout
  // is torn down; with it disabled (idleMillis==0) the same idle link stays up.
  @Test
  void idleTeardownOnlyWhenEnabled() throws Exception {
    long now = System.currentTimeMillis();

    Node enabled = bareNode();
    enabled.useTunablesForTest(Tunables.forTest(1_000_000L, 100L));
    try(ServerSocket ss = new ServerSocket(0)) {
      Socket[] p = loopbackPair(ss);
      Object link = peerLink(enabled, "peer", p[0], true);
      registerLink(enabled, "peer", link);
      setLong(link, "lastInboundMillis", now);        // not probe-dead
      setLong(link, "lastDataMillis", now - 5000);    // idle
      sweep(enabled, now, link);
      assertFalse(routing(enabled).isNeighbor("peer"),
          "idle link not torn down when idle teardown is enabled");
      for(Socket s : p) s.close();
    } finally {
      enabled.kill();
    }

    Node disabled = bareNode();
    disabled.useTunablesForTest(Tunables.forTest(1_000_000L, 0L)); // idle disabled
    try(ServerSocket ss = new ServerSocket(0)) {
      Socket[] p = loopbackPair(ss);
      Object link = peerLink(disabled, "peer", p[0], true);
      registerLink(disabled, "peer", link);
      setLong(link, "lastInboundMillis", now);
      setLong(link, "lastDataMillis", now - 5000);
      sweep(disabled, now, link);
      assertTrue(routing(disabled).isNeighbor("peer"),
          "idle teardown fired even though it is disabled (idleMillis=0)");
      for(Socket s : p) s.close();
    } finally {
      disabled.kill();
    }
  }

  @Test
  void tunablesReadEnvWithDefaults() {
    Tunables t = Tunables.load();
    // No BONEMESH_* env is set in the unit environment, so every knob is its
    // pinned default (protocol.md §0). The env-override path is covered by the
    // interop tiers, which set short values.
    assertTrue(t.probeTimeoutMillis == 15000L && t.idleMillis == 0L
        && t.retryBaseMillis == 500L && t.retryCapMillis == 30000L
        && t.retryMaxMillis == 60000L && t.rekeyMillis == 3600000L
        && t.rekeyFrames == 65536L && t.rekeyTimeoutMillis == 10000L,
        "tunable defaults must match the pinned wire-neutral values");
  }

  private static final String MID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"; // 32 hex

  private static void enqueueRetry(Node n, JSONObject inner) throws Exception {
    Method m = Node.class.getDeclaredMethod("enqueueRetry", JSONObject.class);
    m.setAccessible(true);
    m.invoke(n, inner);
  }

  private static void drainRetries(Node n, long now) throws Exception {
    Method m = Node.class.getDeclaredMethod("drainRetries", long.class);
    m.setAccessible(true);
    m.invoke(n, now);
  }

  private static Map<?, ?> pending(Node n) throws Exception {
    Field f = Node.class.getDeclaredField("pending");
    f.setAccessible(true);
    return (Map<?, ?>) f.get(n);
  }

  // F2: a message that never becomes routable is dropped at its lifetime cap and
  // the origin is told via a synthesized nak{reason:"expired"} on the ack listener.
  @Test
  void retryReportsExpiredToAckListener() throws Exception {
    Node node = bareNode();
    try {
      node.useTunablesForTest(Tunables.forTestRetry(50L, 1L)); // 1 ms lifetime
      AtomicReference<JSONObject> nak = new AtomicReference<>();
      node.addAckListener(nak::set);
      enqueueRetry(node, Messages.data(MID, "self", "ghost", Messages.DEFAULT_TTL, new JSONObject()));
      // Drain at a timestamp past both the first-retry delay and the lifetime.
      drainRetries(node, System.currentTimeMillis() + 1000);
      assertTrue(pending(node).isEmpty(), "expired retry not dropped");
      assertNotNull(nak.get(), "no expiry report delivered to the ack listener");
      assertEquals("nak", nak.get().optString("type"));
      assertEquals("expired", nak.get().optString("reason"));
      assertEquals(MID, nak.get().optString("mid"));
    } finally {
      node.kill();
    }
  }

  // F2 disabled: with retryMaxMillis==0 nothing is queued.
  @Test
  void retryDisabledQueuesNothing() throws Exception {
    Node node = bareNode();
    try {
      node.useTunablesForTest(Tunables.forTestRetry(50L, 0L));
      enqueueRetry(node, Messages.data(MID, "self", "ghost", Messages.DEFAULT_TTL, new JSONObject()));
      assertTrue(pending(node).isEmpty(), "retry queued even though retry is disabled");
    } finally {
      node.kill();
    }
  }
}
