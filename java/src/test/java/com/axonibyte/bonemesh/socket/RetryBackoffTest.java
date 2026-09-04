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

package com.axonibyte.bonemesh.socket;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import com.axonibyte.bonemesh.BoneMesh;
import com.axonibyte.bonemesh.listener.AckListener;
import com.axonibyte.bonemesh.listener.DataListener;

/**
 * Tests for defect D6: the send loop must not busy-retry a dead peer, and a
 * dead peer must not starve delivery to living ones.
 *
 * What this suite does not prove: connect-timeout behavior against a
 * black-holed address (only refused connections are exercised here -- a
 * silently dropping peer belongs to the interop fault-injection tier), and
 * fairness under sustained load. See docs/PLAN.md.
 */
public class RetryBackoffTest {

  private final List<BoneMesh> meshes = new ArrayList<>();

  @AfterEach void tearDown() {
    for(BoneMesh mesh : meshes) mesh.kill();
    meshes.clear();
  }

  private BoneMesh mesh(String label, int port) throws Exception {
    BoneMesh mesh = BoneMesh.build(label, port);
    meshes.add(mesh);
    return mesh;
  }

  private static int freePort() throws IOException {
    try(ServerSocket probe = new ServerSocket(0)) {
      return probe.getLocalPort();
    }
  }

  // Generous because a loaded CI container runs several meshes' worth of
  // daemon threads and ML-KEM keygen at once; the assertion is on convergence
  // happening, not on how fast.
  private static final long CONVERGE_TIMEOUT_MILLIS = 60_000L;

  /** Blocks until {@code from} has learned {@code toLabel}'s pubkey via the
   * discovery handshake -- the precondition for encrypting anything to it --
   * or the timeout elapses. Returns true once the key is known. */
  private static boolean awaitPubkey(BoneMesh from, String toLabel) throws Exception {
    long deadline = System.currentTimeMillis() + CONVERGE_TIMEOUT_MILLIS;
    while(System.currentTimeMillis() < deadline) {
      if(from.getNodeMap().getPubkey(toLabel) != null) return true;
      Thread.sleep(100);
    }
    return from.getNodeMap().getPubkey(toLabel) != null;
  }

  /** Delivers datum to a listener-equipped receiver once the handshake has
   * converged, retrying only across the bounded convergence window. Returns
   * true on delivery. */
  private static boolean deliver(BoneMesh from, String toLabel,
      CountDownLatch received) throws Exception {
    long deadline = System.currentTimeMillis() + CONVERGE_TIMEOUT_MILLIS;
    while(System.currentTimeMillis() < deadline) {
      try {
        from.sendDatum(toLabel, new JSONObject().put("probe", true), false);
      } catch(RuntimeException e) { /* handshake not converged yet */ }
      if(received.await(500, TimeUnit.MILLISECONDS)) return true;
    }
    return false;
  }

  private static final class CountingAckListener implements AckListener {
    private final AtomicInteger naks = new AtomicInteger();
    @Override public void receiveAck(Payload payload) { }
    @Override public void receiveNak(Payload payload) { naks.incrementAndGet(); }
  }

  @Test void deadPeerRetriesAreBackedOffNotBusyLooped() throws Exception {
    int alphaPort = freePort(), betaPort = freePort();
    BoneMesh alpha = mesh("alpha", alphaPort);
    BoneMesh beta = mesh("beta", betaPort);

    CountDownLatch betaGotIt = new CountDownLatch(1);
    beta.addDataListener(json -> betaGotIt.countDown());
    alpha.addNode("beta", "127.0.0.1:" + betaPort);
    assertTrue(awaitPubkey(alpha, "beta"),
        "precondition: handshake never converged (beta's pubkey unknown)");
    assertTrue(deliver(alpha, "beta", betaGotIt),
        "precondition: alpha never delivered to a living beta");

    beta.kill(); // beta's port now refuses connections
    Thread.sleep(250);

    CountingAckListener counter = new CountingAckListener();
    alpha.sendDatum("beta", new JSONObject().put("doomed", true), true, counter);
    Thread.sleep(3_000);

    int naks = counter.naks.get();
    // Precondition first: the retried payload really did fail...
    assertTrue(naks >= 1, "no nak ever arrived; the retry path was not exercised");
    // ...and failed a bounded number of times. The pre-fix client requeued
    // immediately and produced hundreds of naks in this window.
    assertTrue(naks <= 8, "expected backed-off retries, got " + naks + " naks in 3s");
  }

  @Test void deadPeerDoesNotStarveDeliveryToLivingPeer() throws Exception {
    int alphaPort = freePort(), betaPort = freePort(), gammaPort = freePort();
    BoneMesh alpha = mesh("alpha", alphaPort);
    BoneMesh beta = mesh("beta", betaPort);
    BoneMesh gamma = mesh("gamma", gammaPort);

    CountDownLatch betaGotIt = new CountDownLatch(1);
    beta.addDataListener(json -> betaGotIt.countDown());
    alpha.addNode("beta", "127.0.0.1:" + betaPort);
    assertTrue(awaitPubkey(alpha, "beta"),
        "precondition: handshake never converged (beta's pubkey unknown)");
    assertTrue(deliver(alpha, "beta", betaGotIt),
        "precondition: alpha never delivered to a living beta");

    beta.kill();
    Thread.sleep(250);
    alpha.sendDatum("beta", new JSONObject().put("doomed", true), true);

    CountDownLatch gammaGotIt = new CountDownLatch(1);
    gamma.addDataListener(json -> gammaGotIt.countDown());
    alpha.addNode("gamma", "127.0.0.1:" + gammaPort);
    assertTrue(deliver(alpha, "gamma", gammaGotIt),
        "delivery to a living peer starved behind a dead one");
  }
}
