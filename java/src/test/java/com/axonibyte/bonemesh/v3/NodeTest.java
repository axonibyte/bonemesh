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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import com.axonibyte.bonemesh.v3.cert.Certificate;
import com.axonibyte.bonemesh.v3.crypto.Signer;

/**
 * End-to-end node tests over real loopback sockets: two nodes complete the BMX
 * handshake and exchange authenticated, encrypted application messages in both
 * directions, and a three-node line relays a message across an intermediate
 * hop.
 *
 * <p>What this does not prove: behavior under partition, loss, or reordering
 * (the interop harness's job), nor throughput. It proves the v3 stack composes
 * into a working node.</p>
 */
public class NodeTest {

  private static final SecureRandom RNG = new SecureRandom();
  private static final String MESH = "acme-prod";

  private Signer root;
  private byte[] rootPub;
  private final List<Node> nodes = new ArrayList<>();

  private Node node(String label) throws Exception {
    Signer id = Signer.generate(Signer.Level.DSA65, RNG);
    long now = System.currentTimeMillis() / 1000L;
    Certificate cert = new Certificate(MESH, label, id.publicKey(), now - 100, now + 3600).sign(root);
    Node n = Node.start(label, MESH, rootPub, cert, id, 0);
    nodes.add(n);
    return n;
  }

  @AfterEach void tearDown() {
    for(Node n : nodes) n.kill();
    nodes.clear();
  }

  private static boolean await(CountDownLatch latch, long millis) throws InterruptedException {
    return latch.await(millis, TimeUnit.MILLISECONDS);
  }

  private void setUpRoot() {
    root = Signer.generate(Signer.Level.DSA87, RNG);
    rootPub = root.publicKey();
  }

  @Test void twoNodesExchangeMessagesBothDirections() throws Exception {
    setUpRoot();
    Node alpha = node("alpha");
    Node beta = node("beta");

    CountDownLatch betaGot = new CountDownLatch(1);
    CountDownLatch alphaGot = new CountDownLatch(1);
    beta.addDataListener(p -> { if("ping".equals(p.optString("m"))) betaGot.countDown(); });
    alpha.addDataListener(p -> { if("pong".equals(p.optString("m"))) alphaGot.countDown(); });

    alpha.connect("127.0.0.1", beta.port());

    assertTrue(alpha.send("beta", new JSONObject().put("m", "ping")), "alpha could not route to beta");
    assertTrue(await(betaGot, 5000), "beta never received alpha's message");

    assertTrue(beta.send("alpha", new JSONObject().put("m", "pong")), "beta could not route to alpha");
    assertTrue(await(alphaGot, 5000), "alpha never received beta's reply");
  }

  @Test void largePayloadIsChunkedAndReassembledEndToEnd() throws Exception {
    setUpRoot();
    Node alpha = node("alpha");
    Node beta = node("beta");

    // A payload well over the 64 KiB transport frame cap must be chunked by the
    // sender and reassembled by the receiver.
    StringBuilder blob = new StringBuilder();
    for(int i = 0; i < 200_000; i++) blob.append((char) ('a' + (i % 26)));
    String expected = blob.toString();

    CountDownLatch betaGot = new CountDownLatch(1);
    beta.addDataListener(p -> { if(expected.equals(p.optString("blob"))) betaGot.countDown(); });

    alpha.connect("127.0.0.1", beta.port());
    assertTrue(alpha.send("beta", new JSONObject().put("blob", expected)), "could not route large payload");
    assertTrue(await(betaGot, 8000), "beta never reassembled the large payload");
  }

  @Test void threeNodeLineRelaysAcrossTheMiddleHop() throws Exception {
    setUpRoot();
    Node alpha = node("alpha");
    Node beta = node("beta");
    Node gamma = node("gamma");

    CountDownLatch gammaGot = new CountDownLatch(1);
    gamma.addDataListener(p -> { if("relayed".equals(p.optString("m"))) gammaGot.countDown(); });

    // Line topology: alpha <-> beta <-> gamma. Alpha and gamma are not direct
    // neighbors; the message must relay through beta.
    alpha.connect("127.0.0.1", beta.port());
    gamma.connect("127.0.0.1", beta.port());

    // Wait for discovery to give alpha a route to gamma (learned via beta).
    long deadline = System.currentTimeMillis() + 15000;
    boolean routed = false;
    while(System.currentTimeMillis() < deadline) {
      if(alpha.send("gamma", new JSONObject().put("m", "relayed"))) { routed = true; break; }
      Thread.sleep(200);
    }
    assertTrue(routed, "alpha never learned a route to gamma");
    assertTrue(await(gammaGot, 5000), "gamma never received the relayed message");

    // The route to the non-neighbor gamma is via the middle hop beta — the
    // accessor the interop convergence tier reads.
    assertEquals("beta", alpha.routeTable().get("gamma"),
        "alpha's route to gamma should be via beta");
  }
}
