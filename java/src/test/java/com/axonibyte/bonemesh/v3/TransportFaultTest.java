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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Map;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import com.axonibyte.bonemesh.v3.cert.Certificate;
import com.axonibyte.bonemesh.v3.message.Messages;
import com.axonibyte.bonemesh.v3.transport.FrameCodec;
import com.axonibyte.bonemesh.v3.transport.TransportSession;

/**
 * A transport-level fault tears the session down and names the reason
 * (protocol.md §4 and §8).
 *
 * <p>Java already closed on such a fault; what is new is that the peer is told
 * why instead of inferring it from a dropped socket. The injection is a
 * {@code seq} gap rather than a flipped ciphertext byte: it is deterministic and
 * it exercises the ordering rule §4 actually states. Both reach the same catch.
 *
 * <p>What these tests do NOT prove: that the node re-dials and recovers. That is
 * tier 10's job over real sockets. The claim here is narrower — the session is
 * torn down and the reason reaches the far end.
 *
 * @author Caleb L. Power
 */
public final class TransportFaultTest {

  private static final int TIMEOUT_MILLIS = 5000;

  private static Node bareNode() throws Exception {
    Certificate self = new Certificate("m", "self", new byte[0], 0, 0);
    com.axonibyte.bonemesh.v3.crypto.Signer id = com.axonibyte.bonemesh.v3.crypto.Signer.generate(
        com.axonibyte.bonemesh.v3.crypto.Signer.Level.DSA65, new java.security.SecureRandom());
    return Node.start("self", "m", new byte[0], self, id, 0);
  }

  private static Object session(String peer) throws Exception {
    Class<?> sessClass = Class.forName("com.axonibyte.bonemesh.v3.handshake.Session");
    Constructor<?> ctor = sessClass.getDeclaredConstructor(
        byte[].class, byte[].class, Certificate.class, byte[].class);
    ctor.setAccessible(true);
    return ctor.newInstance(new byte[32], new byte[32],
        new Certificate("m", peer, new byte[0], 0, 0), new byte[32]);
  }

  private static Object peerLink(Node node, String peer, Socket socket) throws Exception {
    Class<?> plClass = Class.forName("com.axonibyte.bonemesh.v3.Node$PeerLink");
    Class<?> tsClass = Class.forName("com.axonibyte.bonemesh.v3.transport.TransportSession");
    Class<?> sessClass = Class.forName("com.axonibyte.bonemesh.v3.handshake.Session");
    Object ts = tsClass.getConstructor(sessClass).newInstance(session(peer));
    Constructor<?> plCtor = plClass.getDeclaredConstructor(
        Node.class, String.class, Socket.class, tsClass, boolean.class, String.class);
    plCtor.setAccessible(true);
    return plCtor.newInstance(node, peer, socket, ts, true, "0000000000000000");
  }

  private static void registerLink(Node node, String peer, Object link) throws Exception {
    Method m = Node.class.getDeclaredMethod("registerLink", String.class,
        Class.forName("com.axonibyte.bonemesh.v3.Node$PeerLink"));
    m.setAccessible(true);
    m.invoke(node, peer, link);
  }

  private static Thread startReadLoop(Object link) throws Exception {
    Method m = link.getClass().getDeclaredMethod("readLoop");
    m.setAccessible(true);
    Thread t = new Thread(() -> {
      try {
        m.invoke(link);
      } catch(Exception ignored) { }
    }, "test-read-loop");
    t.setDaemon(true);
    t.start();
    return t;
  }

  @SuppressWarnings("unchecked")
  private static Map<String, ?> links(Node node) throws Exception {
    Field f = Node.class.getDeclaredField("links");
    f.setAccessible(true);
    return (Map<String, ?>) f.get(node);
  }

  private static boolean waitGone(Node node, String peer) throws Exception {
    long deadline = System.currentTimeMillis() + TIMEOUT_MILLIS;
    while(System.currentTimeMillis() < deadline) {
      Map<String, ?> m = links(node);
      synchronized(m) {
        if(!m.containsKey(peer)) return true;
      }
      Thread.sleep(20);
    }
    return false;
  }

  /** The peer-side mirror of the node's session: both keys are all zero. */
  private static TransportSession mirror() throws Exception {
    Class<?> sessClass = Class.forName("com.axonibyte.bonemesh.v3.handshake.Session");
    return (TransportSession) TransportSession.class.getConstructor(sessClass)
        .newInstance(session("self"));
  }

  /**
   * Reads inner messages until a {@code bye} arrives or {@code windowMillis}
   * elapses.
   *
   * <p>Frames must be opened in arrival order (§4's window is exactly one), and a
   * live node's heartbeat interleaves probe and disco traffic with whatever the
   * test is waiting for — so the oracle cannot be "the next frame is the bye".
   *
   * <p>The window is wall-clock rather than a per-read timeout: the heartbeat
   * ticks about as often as any short socket timeout, so a rolling timeout would
   * keep the loop alive long enough for the 15&nbsp;s probe-timeout sweep to close
   * the link, and a test waiting for "no bye" would then see a teardown it did not
   * cause.
   *
   * @return the bye, or null if none arrived inside the window
   */
  private static JSONObject readUntilBye(Socket peerSide, TransportSession peer,
      long windowMillis) throws Exception {
    long deadline = System.currentTimeMillis() + windowMillis;
    for(;;) {
      long left = deadline - System.currentTimeMillis();
      if(left <= 0) return null;
      peerSide.setSoTimeout((int) Math.min(left, 500));
      try {
        JSONObject inner = peer.open(FrameCodec.readFrame(peerSide.getInputStream(),
            FrameCodec.TRANSPORT_CAP));
        if("bye".equals(inner.optString("type"))) return inner;
      } catch(java.net.SocketTimeoutException retry) {
        // no frame in this slice; keep waiting until the window closes
      } catch(java.io.IOException closed) {
        return null;
      }
    }
  }

  @Test
  void anOutOfOrderFrameTearsTheSessionDownNamingProtocolError() throws Exception {
    Node node = bareNode();
    try(ServerSocket ss = new ServerSocket(0)) {
      Socket nodeSide = new Socket();
      nodeSide.connect(new InetSocketAddress("127.0.0.1", ss.getLocalPort()));
      Socket peerSide = ss.accept();

      Object link = peerLink(node, "peer", nodeSide);
      registerLink(node, "peer", link);
      startReadLoop(link);

      TransportSession peer = mirror();
      peer.seal(new JSONObject().put("type", "probe").put("token", 1)); // burns seq 0
      JSONObject gap = peer.seal(Messages.data("m-gap", "peer", "self", 16,
          new JSONObject().put("x", 1)));
      FrameCodec.writeFrame(peerSide.getOutputStream(), gap, FrameCodec.TRANSPORT_CAP);

      // Oracle 1: the reason is read off the wire, not inferred from the close.
      JSONObject inner = readUntilBye(peerSide, peer, TIMEOUT_MILLIS);
      assertNotNull(inner, "the node closed the session without saying why");
      assertEquals("protocol-error", inner.optString("reason"),
          "wrong close reason: " + inner);

      // Oracle 2: the session is gone, not merely silent.
      assertTrue(waitGone(node, "peer"),
          "the node kept a session whose nonce stream it can never follow again");
    } finally {
      node.kill();
    }
  }

  /**
   * §8 requires ignoring inner types a node does not recognize, so an unknown
   * type is NOT a protocol error. This guards the test above: making every
   * unparseable thing close the link would break forward compatibility.
   */
  @Test
  void anUnrecognizedInnerTypeDoesNotCloseTheSession() throws Exception {
    Node node = bareNode();
    try(ServerSocket ss = new ServerSocket(0)) {
      Socket nodeSide = new Socket();
      nodeSide.connect(new InetSocketAddress("127.0.0.1", ss.getLocalPort()));
      Socket peerSide = ss.accept();

      Object link = peerLink(node, "peer", nodeSide);
      registerLink(node, "peer", link);
      startReadLoop(link);

      TransportSession peer = mirror();
      FrameCodec.writeFrame(peerSide.getOutputStream(),
          peer.seal(new JSONObject().put("type", "quux-from-the-future").put("mid", "m1")),
          FrameCodec.TRANSPORT_CAP);

      // Assert the absence with time allowed to pass: no bye is sent. Heartbeat
      // probe and disco traffic is expected and is not a close.
      assertNull(readUntilBye(peerSide, peer, 2000),
          "the node sent a bye over an inner type it is required to ignore");
      Map<String, ?> m = links(node);
      boolean present;
      synchronized(m) {
        present = m.containsKey("peer");
      }
      assertTrue(present, "the node closed a session over an inner type it must ignore");

      // And the link still carries traffic, rather than merely still being listed.
      Method send = link.getClass().getDeclaredMethod("send", JSONObject.class);
      send.setAccessible(true);
      assertTrue((Boolean) send.invoke(link, Messages.bye("idle")),
          "the link survived the unknown type but could no longer be written to");
      JSONObject echoed = readUntilBye(peerSide, peer, TIMEOUT_MILLIS);
      assertNotNull(echoed,
          "the link survived but its frames no longer open on the peer side");
      assertEquals("idle", echoed.optString("reason"),
          "the peer read a different frame than the one just written: " + echoed);
    } finally {
      node.kill();
    }
  }
}
